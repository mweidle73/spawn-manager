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

with GNAT.OS_Lib;

with Anet.Streams;
with Anet.OS;
with Anet.Util;

with Spawn.Types;

package body Spawn.Pool is

   Mngr_Bin  : constant String := "spawn_manager";
   Addr_Base : constant String := "spawn_manager-";

   package Socket_Map_Package is new Ada.Containers.Ordered_Maps
     (Key_Type     => Unbounded_String,
      Element_Type => Socket_Container);
   package SOMP renames Socket_Map_Package;

   protected Sockets
   is
      procedure Insert_Socket (S : Socket_Container);
      --  Insert new socket into store.

      procedure Get_Socket (S : out Socket_Container);
      --  Return non-busy socket container from socket store.

      procedure Release_Socket (C : Socket_Container);
      --  Release given socket container.

      procedure Cleanup;
      --  Cleanup socket store.
   private
      Data : SOMP.Map;
   end Sockets;

   -------------------------------------------------------------------------

   procedure Cleanup
   is
   begin
      Sockets.Cleanup;
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

   procedure Execute
     (Command   : String;
      Directory : String  := Ada.Directories.Current_Directory;
      Timeout   : Integer := -1;
      Pid_Setup : access procedure
        (Pid : GNAT.Expect.Process_Descriptor) := No_Pid_Setup'Access)
   is
      Stream  : aliased Anet.Streams.Memory_Stream_Type
        (Max_Elements => Cmd_Buffer_Size);
      Reply   : Types.Data_Type;
      Request : constant Types.Data_Type
        := (Timeout => Timeout,
            Command => To_Unbounded_String (Command),
            Dir     => To_Unbounded_String (Directory),
            others  => <>);
      S   : Socket_Container;
   begin
      L (Msg => "Executing command '" & Command & "'");

      Types.Data_Type'Write (Stream'Access, Request);

      Sockets.Get_Socket (S);

      Pid_Setup (S.Pid);

      declare
         Rcv_Data : constant Ada.Streams.Stream_Element_Array
           := Send_Receive (Cont    => S,
                            Request => Stream.Get_Buffer);
      begin
         Stream.Set_Buffer (Buffer => Rcv_Data);
         Types.Data_Type'Read (Stream'Access, Reply);
      end;

      if not Reply.Success then
         raise Command_Failed with "Command failed: '" & Command & "'";
      end if;
   end Execute;

   -------------------------------------------------------------------------

   procedure Init
     (Manager_Count  : Positive      := 1;
      Socket_Dir     : String        := "/tmp";
      Socket_Timeout : Duration      := 3.0;
      Buffer_Size    : Positive      := 8192;
      Log            : Log_Procedure := No_Log'Access)
   is
      Args : GNAT.OS_Lib.Argument_List_Access;
   begin
      L := Log;
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

            Args := GNAT.OS_Lib.Argument_String_To_List
              (Arg_String => Mngr_Bin & Buffer_Size'Img & " " & Addr);

            begin
               GNAT.Expect.Non_Blocking_Spawn
                 (Descriptor  => Pid,
                  Command     => Args (Args'First).all,
                  Args        => Args (Args'First + 1 .. Args'Last),
                  Buffer_Size => 0);
               L (Msg => "Forked manager " & Addr);

            exception
               when GNAT.Expect.Invalid_Process =>
                  GNAT.OS_Lib.Free (Args);
                  raise Command_Failed with "Unable to fork " & Mngr_Bin;
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
               Connect_Retry_On_Refused
                 (Socket => Sock,
                  Path   => Anet.Sockets.Unix.Path_Type (Addr),
                  Count  => 5);
               Sockets.Insert_Socket
                 (S => (Address   => To_Unbounded_String (Addr),
                        Pid       => Pid,
                        Socket    => Sock,
                        Available => True));
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

   function Send_Receive
     (Cont    : Socket_Container;
      Request : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      use type Ada.Streams.Stream_Element_Offset;

   begin
      L (Msg => "Sending request using socket " & To_String (Cont.Address));

      Cont.Socket.Send (Item => Request);

      Receive_Reponse :
      declare
         Response : Ada.Streams.Stream_Element_Array (1 .. 32);
         Last_Idx : Ada.Streams.Stream_Element_Offset;
      begin
         Cont.Socket.Receive (Item => Response,
                              Last => Last_Idx);
         if Last_Idx = 0 then
            L (Msg => "Zero response, connection closed by peer");
            raise Command_Failed with "Zero response, connection closed by"
              & " peer";
         end if;

         Sockets.Release_Socket (C => Cont);

         return Response (Response'First .. Last_Idx);
      end Receive_Reponse;

   exception
      when others =>
         Log_A_File (Filename => To_String (Cont.Address & ".log"));
         raise;
   end Send_Receive;

   -------------------------------------------------------------------------

   protected body Sockets
   is
      -------------------------------------------------------------------------

      procedure Cleanup
      is
         E     : Socket_Container;
         Pos   : SOMP.Cursor := Data.First;
         Match : GNAT.Expect.Expect_Match := 0;
      begin
         while SOMP.Has_Element (Position => Pos) loop
            E := SOMP.Element (Position => Pos);

            --  Send termination signal to manager, wait max. 3 seconds for it
            --  to comply.

            GNAT.Expect.Interrupt (Descriptor => E.Pid);

            begin
               GNAT.Expect.Expect
                 (Descriptor => E.Pid,
                  Result     => Match,
                  Regexp     => "",
                  Timeout    => 3000);

            exception
               when GNAT.Expect.Process_Died =>
                  L (Msg => "Manager " & To_String (E.Address)
                     & " terminated");
                  GNAT.Expect.Close (Descriptor => E.Pid);
            end;

            case Match is
               when GNAT.Expect.Expect_Timeout =>
                  L (Msg => "Timeout occured, KILL manager" & " "
                     & To_String (E.Address));
                  GNAT.Expect.Close (Descriptor => E.Pid);
               when others => null;
            end case;

            E.Socket.Close;
            --  A manager may have changed its current directory while using
            --  a relative address. Remove the stored address from the pool's
            --  stable working directory after the manager has terminated.
            Anet.OS.Delete_File (Filename => To_String (E.Address));
            Free (X => E.Socket);
            SOMP.Next (Position => Pos);
         end loop;

         Data.Clear;
      end Cleanup;

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
         while SOMP.Has_Element (Position => Pos) loop
            S := SOMP.Element (Position => Pos);
            if S.Available then
               Data.Update_Element (Position => Pos,
                                    Process  => Set_Busy'Access);
               Found := True;
               exit;
            end if;
            SOMP.Next (Position => Pos);
         end loop;

         if not Found then
            raise Pool_Error with
              "No free spawn manager available, increase the pool size";
         end if;

         L (Msg => "Found available socket " & To_String (S.Address));
      end Get_Socket;

      -------------------------------------------------------------------------

      procedure Insert_Socket (S : Socket_Container)
      is
      begin
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
         Data.Update_Element (Position => Pos,
                              Process  => Set_Available'Access);
         L (Msg => "Socket " & To_String
            (SOMP.Element (Position => Pos).Address) & " released");
      end Release_Socket;
   end Sockets;

end Spawn.Pool;
