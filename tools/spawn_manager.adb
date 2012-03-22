--
--  Process Spawn Manager
--
--  Copyright (C) 2012 Reto Buerki <reet@codelabs.ch>
--  Copyright (C) 2012 secunet Security Networks AG
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

with Ada.Command_Line;
with Ada.Strings.Unbounded;
with Ada.Directories;
with Ada.Streams;
with Ada.Exceptions;

with GNAT.OS_Lib;
with GNAT.Expect;

with Anet.Sockets;
with Anet.Streams;

with Spawn.Types;
with Spawn.Utils;
with Spawn.Logger;
with Spawn.Signals;

procedure Spawn_Manager
is
   use Ada.Strings.Unbounded;

   package L renames Spawn.Logger;

   function S
     (Source : Unbounded_String)
      return String
      renames Ada.Strings.Unbounded.To_String;

   Shell : constant String := "/bin/bash";

   Sock_Listen, Sock_Comm : aliased Anet.Sockets.Socket_Type;

   Stream : aliased Anet.Streams.Memory_Stream_Type (Max_Elements => 8192);
   --  In-memory stream used for request/response serialization.

   procedure Send_Reply (Success : Boolean);
   --  Send reply message indicating success or failure.

   procedure Send_Reply (Success : Boolean)
   is
      Reply : constant Spawn.Types.Data_Type
        := (Success => Success,
            others  => <>);
   begin
      Stream.Clear;
      Spawn.Types.Data_Type'Write (Stream'Access, Reply);
      Sock_Comm.Send (Item => Stream.Get_Buffer);
      pragma Debug (L.Log_File ("Reply sent [" & Success'Img & "]"));
   end Send_Reply;

begin
   if Ada.Command_Line.Argument_Count /= 1 then
      Ada.Command_Line.Set_Exit_Status (Code => Ada.Command_Line.Failure);
      return;
   end if;

   if not Anet.Sockets.Is_Valid_Unix
     (Path => Ada.Command_Line.Argument (1))
   then
      Ada.Command_Line.Set_Exit_Status (Code => Ada.Command_Line.Failure);
      return;
   end if;

   Spawn.Utils.Expand_Search_Path
     (Cmd_Path => Ada.Command_Line.Command_Name);

   Sock_Listen.Create (Family => Anet.Sockets.Family_Unix,
                       Mode   => Anet.Sockets.Stream_Socket);

   pragma Debug (L.Init_Logfile
                 (Path => Ada.Command_Line.Argument (1) & ".log"));
   declare
      Wrapper        : constant String := Spawn.Utils.Locate_Exec_On_Path
        (Name => "spawn_wrapper");
      Socket_Path    : constant String := Ada.Command_Line.Argument (1);
      Signal_Handler : Spawn.Signals.Exit_Handler_Type
        (Socket_L => Sock_Listen'Access,
         Socket_C => Sock_Comm'Access);
      pragma Unreserve_All_Interrupts;
   begin
      Sock_Listen.Bind_Unix (Path => Anet.Sockets.Unix_Path_Type
                             (Socket_Path));
      pragma Debug (L.Log_File ("Listening on socket " & Socket_Path));
      Sock_Listen.Listen;

      Sock_Listen.Accept_Connection (New_Socket => Sock_Comm);
      pragma Debug (L.Log_File ("Connection established"));

      Main :
      loop
         declare
            use type Ada.Streams.Stream_Element_Offset;

            Buffer   : Ada.Streams.Stream_Element_Array (1 .. 8192);
            Last_Idx : Ada.Streams.Stream_Element_Offset;
            Req      : Spawn.Types.Data_Type;
            Sender   : Anet.Sockets.Socket_Addr_Type;
         begin
            pragma Debug (L.Log_File ("Waiting for data"));
            Sock_Comm.Receive (Src  => Sender,
                               Item => Buffer,
                               Last => Last_Idx);

            pragma Debug (L.Log_File ("Received" & Last_Idx'Img & " byte(s)"));
            exit Main when Last_Idx = 0;

            Stream.Set_Buffer (Buffer => Buffer (Buffer'First .. Last_Idx));
            Spawn.Types.Data_Type'Read (Stream'Access, Req);
            if Length (Req.Command) <= 1 then
               raise Constraint_Error with "Invalid command of length"
                 & Length (Req.Command)'Img & " received";
            end if;

            pragma Debug (L.Log_File ("Command request received:"));
            pragma Debug (L.Log_File ("- CMD  [" & S (Req.Command) & "]"));
            pragma Debug (L.Log_File ("- DIR  [" & S (Req.Dir) & "]"));

            declare
               Args  : GNAT.OS_Lib.Argument_List (1 .. 5);
               Pd    : GNAT.Expect.Process_Descriptor;
               Match : GNAT.Expect.Expect_Match := 0;
               Cmd   : constant String          := To_String (Req.Command);
               Dir   : constant String          := To_String (Req.Dir);
               Res   : Integer                  := 1;
            begin
               if Dir'Length /= 0
                 and then Dir /= Ada.Directories.Current_Directory
               then
                  Ada.Directories.Set_Directory (Directory => Dir);
               end if;

               Args (1) := new String'(Shell);
               Args (2) := new String'("-o");
               Args (3) := new String'("pipefail");
               Args (4) := new String'("-c");
               Args (5) := new String'(Cmd);

               GNAT.Expect.Non_Blocking_Spawn
                 (Descriptor  => Pd,
                  Command     => Wrapper,
                  Args        => Args,
                  Buffer_Size => 0);
               Signal_Handler.Set_Running (Descriptor => Pd);
               pragma Debug (L.Log_File ("Command spawned (pid"
                 & GNAT.Expect.Get_Pid (Descriptor => Pd)'Img & ")"));

               --  Close input fd explicitly, see GNAT tracker ticket L321-030.

               GNAT.OS_Lib.Close (FD => GNAT.Expect.Get_Input_Fd
                                  (Descriptor => Pd));

               begin
                  GNAT.Expect.Expect
                    (Descriptor => Pd,
                     Result     => Match,
                     Regexp     => "",
                     Timeout    => Req.Timeout);

               exception
                  when GNAT.Expect.Process_Died =>
                     GNAT.Expect.Close (Descriptor => Pd,
                                        Status     => Res);
                     pragma Debug (L.Log_File ("Command terminated (pid"
                       & GNAT.Expect.Get_Pid (Descriptor => Pd)'Img
                       & ", code" & Res'Img & ")"));
               end;

               case Match is
                  when GNAT.Expect.Expect_Timeout =>
                     pragma Debug (L.Log_File ("Command timeout (pid"
                       & GNAT.Expect.Get_Pid (Descriptor => Pd)'Img & ")"));
                     GNAT.Expect.Close (Descriptor => Pd);
                  when others => null;
               end case;

               Signal_Handler.Stopped;

               for A in Args'Range loop
                  GNAT.OS_Lib.Free (X => Args (A));
               end loop;

               Send_Reply (Success => Res = 0);

            exception
               when GNAT.Expect.Invalid_Process =>
                  pragma Debug (L.Log_File ("Could not spawn process " & Cmd));
                  Send_Reply (Success => False);
            end;

         exception
            when E : others =>
               pragma Debug (L.Log_File ("Exception in main loop:"));
               pragma Debug
                 (L.Log_File (Ada.Exceptions.Exception_Information (E)));
               Send_Reply (Success => False);
         end;
      end loop Main;

      pragma Debug (L.Log_File ("Shutting down"));
      Ada.Command_Line.Set_Exit_Status (Code => Ada.Command_Line.Success);
   end;

exception
   when E : others =>
      pragma Debug (L.Log_File ("Unhandled exception:"));
      pragma Debug (L.Log_File (Ada.Exceptions.Exception_Information (E)));
      raise;
end Spawn_Manager;
