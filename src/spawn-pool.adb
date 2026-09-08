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
with Interfaces.C;
with Interfaces.C.Strings;

with GNAT.OS_Lib;

with Anet.OS;
with Anet.Util;

with Spawn.Transport;

package body Spawn.Pool is

   package C renames Interfaces.C;
   package CS renames Interfaces.C.Strings;

   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_32;
   use type C.int;
   use type CS.chars_ptr;
   use type GNAT.OS_Lib.Argument_List_Access;
   use type Spawn.Protocol.Result_Kind;

   Addr_Base : constant String := "m-";
   Pool_Base : constant String := ".sp-";

   function C_Mkdir (Path : CS.chars_ptr; Mode : C.unsigned) return C.int
     with Import,
          Convention    => C,
          External_Name => "mkdir";

   package Socket_Map_Package is new Ada.Containers.Ordered_Maps
     (Key_Type     => Unbounded_String,
      Element_Type => Socket_Container);
   package SOMP renames Socket_Map_Package;

   procedure Create_Private_Directory (Path : String);
   --  Atomically create Path with no group or other access.

   procedure Remove_Pool_Directory (Path : String);
   --  Remove an empty private socket directory without aborting cleanup.

   function Result_Timeout
     (Child_Timeout : Protocol.Timeout_Milliseconds)
      return Protocol.Timeout_Milliseconds;
   --  Bound the first result byte after a finite child deadline.

   protected Sockets
   is
      procedure Abandon_Socket (C : Socket_Container);
      --  Return one failed lease without making its manager reusable.

      procedure Begin_Cleanup
        (Snapshot       : out SOMP.Map;
         Pool_Directory : out Unbounded_String);
      --  Stop new leases and snapshot managers for out-of-lock cancellation.

      procedure Finish_Cleanup;
      --  Clear manager state after all out-of-lock cleanup has completed.

      procedure Insert_Socket (S : Socket_Container);
      --  Insert new socket into store.

      procedure Get_Socket (S : out Socket_Container);
      --  Return non-busy socket container from socket store.

      procedure Release_Socket (C : Socket_Container);
      --  Release given socket container.

      procedure Start_Initialization (Pool_Directory : String);
      --  Record one new empty pool's private socket directory.

      entry Wait_For_No_Active;
      --  Wait until every caller has returned or abandoned its lease.
   private
      Active_Count  : Natural := 0;
      Data          : SOMP.Map;
      Directory     : Unbounded_String;
      Shutting_Down : Boolean := False;
   end Sockets;

   -------------------------------------------------------------------------

   procedure Cleanup
   is
      Snapshot       : SOMP.Map;
      Position       : SOMP.Cursor;
      Pool_Directory : Unbounded_String;
   begin
      Sockets.Begin_Cleanup
        (Snapshot       => Snapshot,
         Pool_Directory => Pool_Directory);

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
            Anet.OS.Delete_File
              (Filename => To_String (Manager.Cleanup_Address) & ".log");
            Free (X => Manager.Socket);
         end;
         SOMP.Next (Position => Position);
      end loop;

      Sockets.Finish_Cleanup;
      Remove_Pool_Directory (Path => To_String (Pool_Directory));
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

   procedure Create_Private_Directory (Path : String)
   is
      C_Path : CS.chars_ptr := CS.New_String (Path);
      Result : C.int;
   begin
      Result := C_Mkdir (Path => C_Path, Mode => 8#700#);
      CS.Free (C_Path);
      if Result /= 0 then
         raise Pool_Error with "unable to create private socket directory '"
           & Path & "': " & GNAT.OS_Lib.Errno_Message
             (Err => GNAT.OS_Lib.Errno);
      end if;
   exception
      when others =>
         if C_Path /= CS.Null_Ptr then
            CS.Free (C_Path);
         end if;
         raise;
   end Create_Private_Directory;

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

      --  Check if socket directory exists

      if not Ada.Directories.Exists (Name => Socket_Dir) then
         raise Pool_Error with "Socket directory '" & Socket_Dir
           & "' does not exist";
      end if;

      declare
         Pool_Name : constant String := Pool_Base
           & Anet.Util.Random_String (Len => 12);
         Pool_Address : constant String := Ada.Directories.Compose
           (Containing_Directory => Socket_Dir,
            Name                 => Pool_Name);
         Cleanup_Directory : constant String := Ada.Directories.Compose
           (Containing_Directory => Ada.Directories.Full_Name
              (Name => Socket_Dir),
            Name                 => Pool_Name);
      begin
         Sockets.Start_Initialization
           (Pool_Directory => Cleanup_Directory);
         L := Log;
         Cmd_Buffer_Size := Ada.Streams.Stream_Element_Offset (Buffer_Size);
         begin
            Create_Private_Directory (Path => Pool_Address);
            for M in 1 .. Manager_Count loop
               declare
                  Pid                : GNAT.Expect.Process_Descriptor;
                  Manager_Registered : Boolean := False;
                  Manager_Started    : Boolean := False;
                  Address_Suffix : constant String := Addr_Base
                    & Anet.Util.Random_String (Len => 8);
                  Addr : constant String := Ada.Directories.Compose
                    (Containing_Directory => Pool_Address,
                     Name                 => Address_Suffix);
                  Cleanup_Addr : constant String := Ada.Directories.Compose
                    (Containing_Directory => Cleanup_Directory,
                     Name                 => Address_Suffix);

                  procedure Stop_Unregistered_Manager;
                  --  Reap a manager which failed before insertion in Data.

                  procedure Stop_Unregistered_Manager
                  is
                     Match : GNAT.Expect.Expect_Match := 0;
                  begin
                     if not Manager_Started or else Manager_Registered then
                        return;
                     end if;
                     begin
                        GNAT.Expect.Interrupt (Descriptor => Pid);
                     exception
                        when others => null;
                     end;
                     begin
                        GNAT.Expect.Expect
                          (Descriptor => Pid,
                           Result     => Match,
                           Regexp     => "",
                           Timeout    => 1000);
                     exception
                        when GNAT.Expect.Process_Died => null;
                        when others                  => null;
                     end;
                     begin
                        GNAT.Expect.Close (Descriptor => Pid);
                     exception
                        when others => null;
                     end;
                     Anet.OS.Delete_File (Filename => Cleanup_Addr);
                     Anet.OS.Delete_File (Filename => Cleanup_Addr & ".log");
                  end Stop_Unregistered_Manager;
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
                     Manager_Started := True;
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
                     Sock : Socket_Handle
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
                       (S =>
                           (Address         => To_Unbounded_String (Addr),
                           Cleanup_Address =>
                             To_Unbounded_String (Cleanup_Addr),
                           Pid             => Pid,
                           Socket          => Sock,
                           Available       => True));
                     Manager_Registered := True;
                     L (Msg => "Socket " & Addr & " ready");
                  exception
                     when others =>
                        if not Manager_Registered then
                           Sock.Close;
                           Free (X => Sock);
                           Log_A_File (Filename => Cleanup_Addr & ".log");
                        end if;
                        raise;
                  end;
               exception
                  when others =>
                     if Args /= null then
                        GNAT.OS_Lib.Free (Args);
                     end if;
                     Stop_Unregistered_Manager;
                     raise;
               end;
            end loop;
         exception
            when others =>
               Cleanup;
               raise;
         end;
      end;
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

   procedure Remove_Pool_Directory (Path : String)
   is
   begin
      if Path'Length > 0 then
         Ada.Directories.Delete_Directory (Directory => Path);
      end if;
   exception
      when E : others =>
         L (Msg => "Unable to remove private socket directory '" & Path
            & "': " & Ada.Exceptions.Exception_Message (X => E));
   end Remove_Pool_Directory;

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
            begin
               Log_A_File (Filename => To_String (Cont.Address & ".log"));
            exception
               when others => null;
            end;
            begin
               L (Msg => "Socket " & To_String (Cont.Address) & " abandoned");
            exception
               when others => null;
            end;
            Sockets.Abandon_Socket (C => Cont);
         else
            Log_A_File (Filename => To_String (Cont.Address & ".log"));
         end if;
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

      procedure Begin_Cleanup
        (Snapshot       : out SOMP.Map;
         Pool_Directory : out Unbounded_String)
      is
      begin
         if Shutting_Down then
            raise Pool_Error with "spawn manager cleanup already in progress";
         end if;
         Shutting_Down := True;
         Snapshot := Data;
         Pool_Directory := Directory;
      end Begin_Cleanup;

      ----------------------------------------------------------------------

      procedure Finish_Cleanup
      is
      begin
         Data.Clear;
         Directory := Null_Unbounded_String;
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

      procedure Start_Initialization (Pool_Directory : String)
      is
      begin
         if Shutting_Down or else not Data.Is_Empty then
            raise Pool_Error with "spawn manager pool is already initialized";
         end if;
         Directory := To_Unbounded_String (Pool_Directory);
      end Start_Initialization;

      ----------------------------------------------------------------------

      entry Wait_For_No_Active when Active_Count = 0
      is
      begin
         null;
      end Wait_For_No_Active;
   end Sockets;

end Spawn.Pool;
