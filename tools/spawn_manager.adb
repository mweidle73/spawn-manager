--
--  Process Spawn Manager
--
--  Copyright (C) 2012, 2015 Reto Buerki <reet@codelabs.ch>
--  Copyright (C) 2012, 2015 secunet Security Networks AG
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
with Ada.Command_Line;
with Ada.Strings.Unbounded;
with Ada.Streams;
with Ada.Exceptions;
with Interfaces;

with Anet.Sockets.Unix;
with Anet.Streams;

with Spawn.Types;
with Spawn.Logger;
with Spawn.Signals;
with Spawn.Version;

with Spawn_Manager_Processes;

procedure Spawn_Manager
is
   use Ada.Strings.Unbounded;

   package L renames Spawn.Logger;

   function S
     (Source : Unbounded_String)
      return String
      renames Ada.Strings.Unbounded.To_String;

   Sock_Listen, Sock_Comm : aliased Anet.Sockets.Unix.TCP_Socket_Type;

   procedure Print_Usage;
   --  Print usage to stdout.

   -------------------------------------------------------------------------

   procedure Print_Usage
   is
      use Ada.Command_Line;
   begin
      Ada.Text_IO.Put_Line
        (Item => "Spawn Manager, version " & Spawn.Version.Version_String);
      Ada.Text_IO.Put_Line
        (Item => "Usage: " & Command_Name & " <buffer_size> <socket>");
   end Print_Usage;

   Buffer_Size : Positive;
   Socket_Path : Unbounded_String;
begin
   if Ada.Command_Line.Argument_Count /= 2 then
      Print_Usage;
      Ada.Command_Line.Set_Exit_Status (Code => Ada.Command_Line.Failure);
      return;
   end if;

   Buffer_Size := Positive'Value (Ada.Command_Line.Argument (1));
   Socket_Path := To_Unbounded_String (Ada.Command_Line.Argument (2));

   pragma Debug (L.Init_Logfile
                 (Path => S (Socket_Path) & ".log"));
   pragma Debug (L.Log_File (Message => "Starting Spawn Manager (version "
                             & Spawn.Version.Version_String & ")"));

   if not Anet.Sockets.Unix.Is_Valid (Path => S (Socket_Path))
   then
      pragma Debug (L.Log_File ("UNIX path too long '"
                    & S (Socket_Path) & "'"));
      Ada.Command_Line.Set_Exit_Status (Code => Ada.Command_Line.Failure);
      return;
   end if;

   Sock_Listen.Init;

   declare
      Stream : aliased Anet.Streams.Memory_Stream_Type
        (Max_Elements => Ada.Streams.Stream_Element_Offset (Buffer_Size));
      --  In-memory stream used for request/response serialization.

      procedure Send_Reply (Success : Boolean);
      --  Send reply message indicating success or failure.

      ----------------------------------------------------------------------

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

      Signal_Handler : Spawn.Signals.Exit_Handler_Type
        (Socket_L => Sock_Listen'Access,
         Socket_C => Sock_Comm'Access);
      pragma Unreserve_All_Interrupts;
   begin
      Sock_Listen.Bind (Path => Anet.Sockets.Unix.Path_Type (S (Socket_Path)));
      pragma Debug (L.Log_File ("Listening on socket " & S (Socket_Path)));
      Sock_Listen.Listen;

      Sock_Listen.Accept_Connection (New_Socket => Sock_Comm);
      pragma Debug (L.Log_File ("Connection established"));

      Main :
      loop
         declare
            use type Ada.Streams.Stream_Element_Offset;

            Buffer   : Ada.Streams.Stream_Element_Array
              (1 .. Ada.Streams.Stream_Element_Offset (Buffer_Size));
            Last_Idx : Ada.Streams.Stream_Element_Offset;
            Req      : Spawn.Types.Data_Type;
         begin
            pragma Debug (L.Log_File ("Waiting for data"));
            Sock_Comm.Receive (Item => Buffer,
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
               use type Spawn_Manager_Processes.Termination_Kind;

               Request : constant
                 Spawn_Manager_Processes.Execution_Request
                 := Spawn_Manager_Processes.Create_Shell_Request
                   (Command   => To_String (Req.Command),
                    Directory => To_String (Req.Dir),
                    Timeout   => Interfaces.Integer_64 (Req.Timeout));
               Result : Spawn_Manager_Processes.Execution_Result;
            begin
               Signal_Handler.Set_Running;
               begin
                  Result := Spawn_Manager_Processes.Execute
                    (Request => Request);
               exception
                  when others =>
                     Signal_Handler.Stopped;
                     raise;
               end;
               Signal_Handler.Stopped;
               pragma Debug
                 (L.Log_File
                    ("Command result: "
                     & Spawn_Manager_Processes.Diagnostic (Result)));
               Send_Reply
                 (Success => Result.Kind = Spawn_Manager_Processes.Exited
                  and then Result.Exit_Status = 0);
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
