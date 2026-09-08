--
--  Process Spawn Manager
--
--  Copyright (C) 2012-2016 Reto Buerki <reet@codelabs.ch>
--  Copyright (C) 2012-2016 secunet Security Networks AG
--
--  This program is free software; you can redistribute it and/or
--  modify it under the terms of the GNU General Public License
--  as published by the Free Software Foundation; either version 2
--  of the License, or (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--  GNU General Public License for more details.
--
--  You should have received a copy of the GNU General Public License
--  along with this program; if not, write to the Free Software
--  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
--  USA.
--
--  As a special exception, if other files instantiate generics from this
--  unit,  or  you  link  this  unit  with  other  files  to  produce  an
--  executable   this  unit  does  not  by  itself  cause  the  resulting
--  executable to  be  covered by the  GNU General  Public License.  This
--  exception does  not  however  invalidate  any  other reasons why  the
--  executable file might be covered by the GNU Public License.
--

with Ada.Text_IO;
with Ada.Strings.Fixed;
with Ada.Containers.Ordered_Maps;
with Ada.Exceptions;
with Interfaces;

with GNAT.OS_Lib;

with Anet.OS;
with Anet.Util;

with Spawn.Transport;

package body Spawn.Pool is

   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_32;
   use type Spawn.Protocol.Result_Kind;

   Addr_Base : constant String := "spawn_manager-";

   package Socket_Map_Package is new Ada.Containers.Ordered_Maps
     (Key_Type     => Unbounded_String,
      Element_Type => Socket_Container);
   package SOMP renames Socket_Map_Package;

   function Result_Timeout
     (Child_Timeout : Protocol.Timeout_Milliseconds)
      return Protocol.Timeout_Milliseconds;
   --  Bound the first result byte after a finite child deadline.

   protected Sockets
   is
      procedure Abandon_Socket (C : Socket_Container);
      --  Return one failed lease without making its manager reusable.

      procedure Begin_Cleanup (Snapshot : out SOMP.Map);
      --  Stop new leases and snapshot managers for out-of-lock cancellation.

      procedure Finish_Cleanup;
      --  Clear manager state after all out-of-lock cleanup has completed.

      procedure Insert_Socket (S : Socket_Container);
      --  Insert new socket into store.

      procedure Get_Socket (S : out Socket_Container);
      --  Return non-busy socket container from socket store.

      procedure Release_Socket (C : Socket_Container);
      --  Release given socket container.

      entry Wait_For_No_Active;
      --  Wait until every caller has returned or abandoned its lease.
   private
      Active_Count  : Natural := 0;
      Data          : SOMP.Map;
      Shutting_Down : Boolean := False;
   end Sockets;

   -------------------------------------------------------------------------

   procedure Cleanup
   is
      Snapshot : SOMP.Map;
      Position : SOMP.Cursor;
   begin
      Sockets.Begin_Cleanup (Snapshot => Snapshot);

      --  Cancellation must happen before waiting for active leases: manager
      --  signal handlers close their communication sockets and wake callers.

      Position := Snapshot.First;
      while SOMP.Has_Element (Position => Position) loop
         declare
            Manager : Socket_Container
              := SOMP.Element (Position => Position);
         begin
            begin
               GNAT.Expect.Interrupt (Descriptor => Manager.Pid);
            exception
               when E : others =>
                  L (Msg => "Unable to interrupt manager "
                     & To_String (Manager.Address) & ": "
                     & Ada.Exceptions.Exception_Message (X => E));
            end;
         end;
         SOMP.Next (Position => Position);
      end loop;

      Sockets.Wait_For_No_Active;

      Position := Snapshot.First;
      while SOMP.Has_Element (Position => Position) loop
         declare
            Manager : Socket_Container := SOMP.Element (Position => Position);
            Match   : GNAT.Expect.Expect_Match := 0;
         begin
            begin
               GNAT.Expect.Expect
                 (Descriptor => Manager.Pid,
                  Result     => Match,
                  Regexp     => "",
                  Timeout    => 3000);
            exception
               when GNAT.Expect.Process_Died =>
                  L (Msg => "Manager " & To_String (Manager.Address)
                     & " terminated");
                  GNAT.Expect.Close (Descriptor => Manager.Pid);
            end;

            case Match is
               when GNAT.Expect.Expect_Timeout =>
                  L (Msg => "Timeout occured, KILL manager "
                     & To_String (Manager.Address));
                  GNAT.Expect.Close (Descriptor => Manager.Pid);
               when others => null;
            end case;

            Manager.Socket.Close;
            Remove_Socket_File
              (Filename => To_String (Manager.Cleanup_Address));
            Free (X => Manager.Socket);
         end;
         SOMP.Next (Position => Position);
      end loop;

      Sockets.Finish_Cleanup;
   end Cleanup;

   -------------------------------------------------------------------------

   procedure Connect_Retry_On_Refused
     (Socket : Socket_Handle;
      Path   : Anet.Sockets.Unix.Path_Type;
      Count  : Positive)
   is

      function Is_Refused (Msg : String) return Boolean;
      --  Returns True if the given message contains the pattern 'Connection
      --  refused'.

      function Is_Refused (Msg : String) return Boolean
      is
      begin
         return Ada.Strings.Fixed.Index
           (Source  => Msg,
            Pattern => "Connection refused") > 0;
      end Is_Refused;

      Refused : Boolean;
   begin
      for I in 1 .. Count loop
         Refused := False;

         begin
            Socket.Connect (Path => Path);

         exception
            when E : Anet.Socket_Error =>
               Refused := Is_Refused
                 (Msg => Ada.Exceptions.Exception_Message (X => E));
               if not Refused then
                  raise;
               end if;
         end;

         if not Refused then
            return;
         end if;

         L (Msg => "Socket '" & String (Path) & "' refused "
            & "connection, retrying in one second ...");
         delay 1.0;
      end loop;

      raise Connection_Refused with "Socket '" & String (Path) & "' still "
        & "refuses connection after" & Count'Img & " tries";
   end Connect_Retry_On_Refused;

   -------------------------------------------------------------------------

   procedure Delete_Socket_File (Filename : String)
   is
   begin
      Anet.OS.Delete_File (Filename => Filename);
   end Delete_Socket_File;

   -------------------------------------------------------------------------

   function Execute
     (Request   : Protocol.Exec_Request_Type;
      Pid_Setup : access procedure
        (Pid : GNAT.Expect.Process_Descriptor) := No_Pid_Setup'Access)
      return Protocol.Result_Type
   is
   begin
      declare
         Length : constant Positive := Protocol.Exec_Request_Frame_Length
           (Request      => Request,
            Active_Bound => Positive (Cmd_Buffer_Size));
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
         S : Socket_Container;
      begin
         Protocol.Encode_Exec_Request
           (Request      => Request,
            Active_Bound => Positive (Cmd_Buffer_Size),
            Data         => Data);
         Sockets.Get_Socket (S);
         L (Msg => "Found available socket " & To_String (S.Address));
         begin
            Pid_Setup (S.Pid);
         exception
            when others =>
               Sockets.Abandon_Socket (C => S);
               raise;
         end;
         begin
            return Send_Receive
              (Cont                  => S,
               Request               => Data,
               First_Byte_Timeout_MS =>
                 Result_Timeout (Child_Timeout => Request.Timeout));
         exception
            when Spawn.Protocol.Protocol_Error
               | Spawn.Transport.Extra_Data
               | Spawn.Transport.Peer_Closed
               | Spawn.Transport.Transport_Error
               | Spawn.Transport.Transport_Timeout =>
               return
                 (Kind       => Protocol.Protocol_Failed,
                  Diagnostic => To_Unbounded_String
                    ("manager transport failed"));
         end;
      end;
   exception
      when Spawn.Protocol.Protocol_Error
         | Spawn.Protocol.Request_Error =>
         return
           (Kind       => Protocol.Request_Rejected,
            Diagnostic => To_Unbounded_String ("invalid execution request"));
   end Execute;

   -------------------------------------------------------------------------

   procedure Execute
     (Command   : String;
      Directory : String  := Ada.Directories.Current_Directory;
      Timeout   : Integer := -1;
      Pid_Setup : access procedure
        (Pid : GNAT.Expect.Process_Descriptor) := No_Pid_Setup'Access)
   is
      Request : constant Protocol.Shell_Request_Type
        := (Command   => To_Unbounded_String (Command),
            Directory => To_Unbounded_String (Directory),
            Timeout   => Protocol.Timeout_Milliseconds (Timeout));
      Length : constant Positive := Protocol.Shell_Request_Frame_Length
        (Request      => Request,
         Active_Bound => Positive (Cmd_Buffer_Size));
      Data : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Length));
      S      : Socket_Container;
      Result : Protocol.Result_Type;
   begin
      L (Msg => "Executing command '" & Command & "'");

      Protocol.Encode_Shell_Request
        (Request      => Request,
         Active_Bound => Positive (Cmd_Buffer_Size),
         Data         => Data);

      Sockets.Get_Socket (S);
      L (Msg => "Found available socket " & To_String (S.Address));

      begin
         Pid_Setup (S.Pid);
      exception
         when others =>
            Sockets.Abandon_Socket (C => S);
            raise;
      end;

      begin
         Result := Send_Receive
           (Cont                  => S,
            Request               => Data,
            First_Byte_Timeout_MS =>
              Result_Timeout
                (Child_Timeout => Protocol.Timeout_Milliseconds (Timeout)));
      exception
         when Spawn.Protocol.Protocol_Error
            | Spawn.Transport.Extra_Data
            | Spawn.Transport.Peer_Closed
            | Spawn.Transport.Transport_Error
            | Spawn.Transport.Transport_Timeout =>
            raise Command_Failed with
              "Manager transport failed for command: '" & Command & "'";
      end;

      if Result.Kind /= Protocol.Exited or else Result.Exit_Status /= 0 then
         raise Command_Failed with "Command failed: '" & Command & "'";
      end if;
   end Execute;

   -------------------------------------------------------------------------

   procedure Execute_Checked
     (Request   : Protocol.Exec_Request_Type;
      Pid_Setup : access procedure
        (Pid : GNAT.Expect.Process_Descriptor) := No_Pid_Setup'Access)
   is
      Result : constant Protocol.Result_Type := Execute
        (Request   => Request,
         Pid_Setup => Pid_Setup);
   begin
      if Result.Kind /= Protocol.Exited or else Result.Exit_Status /= 0 then
         raise Command_Failed with "Structured command failed ["
           & Result.Kind'Image & "]";
      end if;
   end Execute_Checked;

   -------------------------------------------------------------------------

   procedure Init
     (Manager_Path   : String;
      Manager_Count  : Positive      := 1;
      Socket_Dir     : String        := "/tmp";
      Socket_Timeout : Duration      := 3.0;
      Buffer_Size    : Positive      := 8192;
      Log            : Log_Procedure := No_Log'Access)
   is
      Args : GNAT.OS_Lib.Argument_List_Access;
   begin
      L := Log;
      if Manager_Path'Length = 0
        or else Manager_Path (Manager_Path'First) /= '/'
      then
         raise Pool_Error with "manager path must be absolute";
      end if;
      if Buffer_Size < Protocol.Header_Size
        or else Buffer_Size > Protocol.Maximum_Frame_Size
      then
         raise Pool_Error with "invalid protocol buffer size";
      end if;
      Cmd_Buffer_Size := Ada.Streams.Stream_Element_Offset (Buffer_Size);

      --  Check if socket directory exists

      if not Ada.Directories.Exists (Name => Socket_Dir) then
         raise Pool_Error with "Socket directory '" & Socket_Dir
           & "' does not exist";
      end if;

      for M in 1 .. Manager_Count loop
         declare
            Pid  : GNAT.Expect.Process_Descriptor;
            Addr : constant String := Socket_Dir & "/" & Addr_Base
              & Anet.Util.Random_String (Len => 8);
         begin
            if not Anet.Sockets.Unix.Is_Valid (Path => Addr) then
               raise Pool_Error with "UNIX path too long '" & Addr & "'";
            end if;

            Args := new GNAT.OS_Lib.Argument_List'
              (new String'(Buffer_Size'Img),
               new String'(Addr));

            begin
               GNAT.Expect.Non_Blocking_Spawn
                  (Descriptor  => Pid,
                  Command     => Manager_Path,
                  Args        => Args.all,
                  Buffer_Size => 0);
               L (Msg => "Forked manager " & Addr);

            exception
               when GNAT.Expect.Invalid_Process =>
                  GNAT.OS_Lib.Free (Args);
                  raise Command_Failed with
                    "Unable to fork manager " & Manager_Path;
            end;

            GNAT.OS_Lib.Free (Args);

            L (Msg =>  "Waiting for socket '" & Addr
               & "' to become available");
            Anet.Util.Wait_For_File (Path     => Addr,
                                     Timespan => Socket_Timeout);

            declare
               Sock : constant Socket_Handle
                 := new Anet.Sockets.Unix.TCP_Socket_Type;
            begin
               Sock.Init;
               Spawn.Transport.Set_Close_On_Exec
                 (Descriptor => Sock.Get_Socket);
               Connect_Retry_On_Refused
                 (Socket => Sock,
                  Path   => Anet.Sockets.Unix.Path_Type (Addr),
                  Count  => 5);
               Sock.Set_Nonblocking_Mode;
               Sockets.Insert_Socket
                 (S => (Address         => To_Unbounded_String (Addr),
                        Cleanup_Address => To_Unbounded_String
                          (Ada.Directories.Full_Name (Name => Addr)),
                        Pid             => Pid,
                        Socket          => Sock,
                        Available       => True));
               L (Msg => "Socket " & Addr & " ready");
            exception
               when others =>
                  Log_A_File (Filename => Addr & ".log");
                  raise;
            end;
         end;
      end loop;
   end Init;

   -------------------------------------------------------------------------

   procedure Log_A_File (Filename : String)
   is
      Log_File : Ada.Text_IO.File_Type;
   begin
      if not Ada.Directories.Exists (Name => Filename) then
         L (Msg => "Unable to log contents of nonexistent file '"
            & Filename & "' - non-debug build?");
         return;
      end if;

      Ada.Text_IO.Open
        (File => Log_File,
         Mode => Ada.Text_IO.In_File,
         Name => Filename,
         Form => "shared=no");

      while not Ada.Text_IO.End_Of_File (File => Log_File) loop
         L (Msg => Filename & ": " & Ada.Text_IO.Get_Line (File => Log_File));
      end loop;

      Ada.Text_IO.Close (File => Log_File);

   exception
      when E : others =>
         if Ada.Text_IO.Is_Open (File => Log_File) then
            Ada.Text_IO.Close (File => Log_File);
         end if;
         L (Msg => "Error logging file contents '"
            & Filename & "': " & Ada.Exceptions.Exception_Message (X => E));
   end Log_A_File;

   -------------------------------------------------------------------------

   procedure Remove_Socket_File (Filename : String)
   is
   begin
      Socket_File_Delete (Filename => Filename);

   exception
      when E : Anet.OS.IO_Error =>
         L (Msg => "Unable to remove manager socket '"
            & Filename & "': "
            & Ada.Exceptions.Exception_Message (X => E));
   end Remove_Socket_File;

   -------------------------------------------------------------------------

   function Result_Timeout
     (Child_Timeout : Protocol.Timeout_Milliseconds)
      return Protocol.Timeout_Milliseconds
   is
   begin
      if Child_Timeout = -1 then
         return -1;
      elsif Child_Timeout
        > Protocol.Timeout_Milliseconds'Last
          - Interfaces.Integer_64
            (Spawn.Transport.Frame_Completion_Timeout_MS)
      then
         return Protocol.Timeout_Milliseconds'Last;
      else
         return Child_Timeout + Interfaces.Integer_64
           (Spawn.Transport.Frame_Completion_Timeout_MS);
      end if;
   end Result_Timeout;

   -------------------------------------------------------------------------

   function Send_Receive
     (Cont    : Socket_Container;
      Request : Ada.Streams.Stream_Element_Array;
      First_Byte_Timeout_MS : Protocol.Timeout_Milliseconds)
      return Protocol.Result_Type
   is
      Result       : Protocol.Result_Type;
      Lease_Active : Boolean := True;
   begin
      L (Msg => "Sending request using socket " & To_String (Cont.Address));

      Spawn.Transport.Send_Frame
        (Descriptor => Cont.Socket.Get_Socket,
         Data       => Request);
      declare
         Response : constant Ada.Streams.Stream_Element_Array
           := Spawn.Transport.Receive_Frame
             (Descriptor            => Cont.Socket.Get_Socket,
              Active_Bound          => Positive (Cmd_Buffer_Size),
              First_Byte_Timeout_MS => First_Byte_Timeout_MS);
      begin
         Spawn.Protocol.Decode_Result
           (Data         => Response,
            Active_Bound => Positive (Cmd_Buffer_Size),
            Result       => Result);
      end;
      Sockets.Release_Socket (C => Cont);
      Lease_Active := False;
      L (Msg => "Socket " & To_String (Cont.Address) & " released");
      return Result;

   exception
      when others =>
         if Lease_Active then
            Sockets.Abandon_Socket (C => Cont);
            L (Msg => "Socket " & To_String (Cont.Address) & " abandoned");
         end if;
         Log_A_File (Filename => To_String (Cont.Address & ".log"));
         raise;
   end Send_Receive;

   -------------------------------------------------------------------------

   protected body Sockets
   is
      -------------------------------------------------------------------------

      procedure Abandon_Socket (C : Socket_Container)
      is
         Position : constant SOMP.Cursor := Data.Find (Key => C.Address);
      begin
         if not SOMP.Has_Element (Position => Position)
           or else Active_Count = 0
         then
            raise Program_Error with "invalid abandoned manager lease";
         end if;
         Active_Count := Active_Count - 1;
      end Abandon_Socket;

      ----------------------------------------------------------------------

      procedure Begin_Cleanup (Snapshot : out SOMP.Map)
      is
      begin
         if Shutting_Down then
            raise Pool_Error with "spawn manager cleanup already in progress";
         end if;
         Shutting_Down := True;
         Snapshot := Data;
      end Begin_Cleanup;

      ----------------------------------------------------------------------

      procedure Finish_Cleanup
      is
      begin
         Data.Clear;
         Shutting_Down := False;
      end Finish_Cleanup;

      ----------------------------------------------------------------------

      procedure Get_Socket (S : out Socket_Container)
      is
         Pos   : SOMP.Cursor := Data.First;
         Found : Boolean     := False;

         procedure Set_Busy
           (Key     :        Unbounded_String;
            Element : in out Socket_Container);
         --  Set state of given socket container to busy.

         procedure Set_Busy
           (Key     :        Unbounded_String;
            Element : in out Socket_Container)
         is
            pragma Unreferenced (Key);
         begin
            Element.Available := False;
         end Set_Busy;
      begin
         if Shutting_Down then
            raise Pool_Error with "spawn manager pool is shutting down";
         end if;
         while SOMP.Has_Element (Position => Pos) loop
            S := SOMP.Element (Position => Pos);
            if S.Available then
               Data.Update_Element (Position => Pos,
                                    Process  => Set_Busy'Access);
               Active_Count := Active_Count + 1;
               Found := True;
               exit;
            end if;
            SOMP.Next (Position => Pos);
         end loop;

         if not Found then
            raise Pool_Error with
              "No free spawn manager available, increase the pool size";
         end if;
      end Get_Socket;

      -------------------------------------------------------------------------

      procedure Insert_Socket (S : Socket_Container)
      is
      begin
         if Shutting_Down then
            raise Pool_Error with "spawn manager pool is shutting down";
         end if;
         Data.Insert (Key      => S.Address,
                      New_Item => S);
      end Insert_Socket;

      ----------------------------------------------------------------------

      procedure Release_Socket (C : Socket_Container)
      is
         procedure Set_Available
           (Key     :        Unbounded_String;
            Element : in out Socket_Container);
         --  Set state of given socket container to available.

         procedure Set_Available
           (Key     :        Unbounded_String;
            Element : in out Socket_Container)
         is
            pragma Unreferenced (Key);
         begin
            Element.Available := True;
         end Set_Available;

         Pos : constant SOMP.Cursor := Data.Find (Key => C.Address);
      begin
         if not SOMP.Has_Element (Position => Pos)
           or else Active_Count = 0
         then
            raise Program_Error with "invalid released manager lease";
         end if;
         if not Shutting_Down then
            Data.Update_Element (Position => Pos,
                                 Process  => Set_Available'Access);
         end if;
         Active_Count := Active_Count - 1;
      end Release_Socket;

      ----------------------------------------------------------------------

      entry Wait_For_No_Active when Active_Count = 0
      is
      begin
         null;
      end Wait_For_No_Active;
   end Sockets;

end Spawn.Pool;
