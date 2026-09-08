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

with Anet.Sockets;
with Anet.Sockets.Unix;

with Spawn.Logger;
with Spawn.Protocol;
with Spawn.Signals;
with Spawn.Transport;
with Spawn.Version;

with Spawn_Manager_Processes;

procedure Spawn_Manager
is
   use Ada.Strings.Unbounded;
   use type Ada.Streams.Stream_Element_Offset;

   package L renames Spawn.Logger;

   function S
     (Source : Unbounded_String)
      return String
      renames Ada.Strings.Unbounded.To_String;

   Sock_Listen, Sock_Comm : aliased Anet.Sockets.Unix.TCP_Socket_Type;

   procedure Print_Usage;
   --  Print usage to stdout.

   function To_Protocol_Result
     (Result : Spawn_Manager_Processes.Execution_Result)
      return Spawn.Protocol.Result_Type;
   --  Translate the common execution result without losing termination data.

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

   -------------------------------------------------------------------------

   function To_Protocol_Result
     (Result : Spawn_Manager_Processes.Execution_Result)
      return Spawn.Protocol.Result_Type
   is
   begin
      case Result.Kind is
         when Spawn_Manager_Processes.Exited =>
            return
              (Kind        => Spawn.Protocol.Exited,
               Exit_Status => Interfaces.Unsigned_32 (Result.Exit_Status));
         when Spawn_Manager_Processes.Signaled =>
            return
              (Kind          => Spawn.Protocol.Signaled,
               Signal_Number => Interfaces.Unsigned_16
                 (Result.Signal_Number));
         when Spawn_Manager_Processes.Timed_Out =>
            return (Kind => Spawn.Protocol.Timed_Out);
         when Spawn_Manager_Processes.Spawn_Failed
            | Spawn_Manager_Processes.Internal_Error =>
            return
              (Kind    => Spawn.Protocol.Spawn_Failed,
               Failure =>
                 (Stage => Spawn.Protocol.Failure_Stage'Val
                    (Spawn_Manager_Processes.Failure_Stage'Pos
                       (Result.Stage)),
                  Error_Number => Interfaces.Unsigned_32
                    (Result.Error_Number),
                  Diagnostic => To_Unbounded_String
                    (Spawn_Manager_Processes.Diagnostic (Result))));
      end case;
   end To_Protocol_Result;

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
   Spawn.Transport.Set_Close_On_Exec
     (Descriptor => Sock_Listen.Get_Socket);

   declare
      Signal_Handler : Spawn.Signals.Exit_Handler_Type
        (Socket_L => Sock_Listen'Access,
         Socket_C => Sock_Comm'Access);
      pragma Unreserve_All_Interrupts;

      function Execute_Request
        (Request : Spawn_Manager_Processes.Execution_Request)
         return Spawn_Manager_Processes.Execution_Result;
      --  Execute either request kind under the same signal-state boundary.

      procedure Send_Reply (Result : Spawn.Protocol.Result_Type);
      --  Send one exact structured result frame.

      procedure Send_Reply_Protocol_Failure (Diagnostic : String);
      --  Attempt a terminal diagnostic without masking the original error.

      ----------------------------------------------------------------------

      function Execute_Request
        (Request : Spawn_Manager_Processes.Execution_Request)
         return Spawn_Manager_Processes.Execution_Result
      is
         Result : Spawn_Manager_Processes.Execution_Result;
      begin
         Signal_Handler.Set_Running;
         begin
            Result := Spawn_Manager_Processes.Execute (Request => Request);
         exception
            when others =>
               Signal_Handler.Stopped;
               raise;
         end;
         Signal_Handler.Stopped;
         return Result;
      end Execute_Request;

      ----------------------------------------------------------------------

      procedure Send_Reply (Result : Spawn.Protocol.Result_Type)
      is
         Length : constant Positive := Spawn.Protocol.Result_Frame_Length
           (Result       => Result,
            Active_Bound => Buffer_Size);
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
      begin
         Spawn.Protocol.Encode_Result
           (Result       => Result,
            Active_Bound => Buffer_Size,
            Data         => Data);
         Spawn.Transport.Send_Frame
           (Descriptor => Sock_Comm.Get_Socket,
            Data       => Data);
         pragma Debug (L.Log_File ("Result sent [" & Result.Kind'Image & "]"));
      end Send_Reply;

      ----------------------------------------------------------------------

      procedure Send_Reply_Protocol_Failure (Diagnostic : String)
      is
      begin
         Send_Reply
           (Result =>
              (Kind       => Spawn.Protocol.Protocol_Failed,
               Diagnostic => To_Unbounded_String (Diagnostic)));
      exception
         when others => null;
      end Send_Reply_Protocol_Failure;

   begin
      Sock_Listen.Bind (Path => Anet.Sockets.Unix.Path_Type (S (Socket_Path)));
      pragma Debug (L.Log_File ("Listening on socket " & S (Socket_Path)));
      Sock_Listen.Listen;

      Sock_Listen.Accept_Connection (New_Socket => Sock_Comm);
      Spawn.Transport.Set_Close_On_Exec
        (Descriptor => Sock_Comm.Get_Socket);
      Sock_Comm.Set_Nonblocking_Mode;
      pragma Debug (L.Log_File ("Connection established"));

      Main :
      loop
         begin
            pragma Debug (L.Log_File ("Waiting for data"));
            declare
               Frame : constant Ada.Streams.Stream_Element_Array
                 := Spawn.Transport.Receive_Frame
                   (Descriptor   => Sock_Comm.Get_Socket,
                    Active_Bound => Buffer_Size);
               Header : Spawn.Protocol.Header_Type;
            begin
               pragma Debug (L.Log_File ("Received" & Frame'Length'Img
                             & " byte(s)"));
               Spawn.Protocol.Decode_Header
                 (Data         => Frame
                    (Frame'First .. Frame'First
                     + Spawn.Protocol.Header_Size - 1),
                  Active_Bound => Buffer_Size,
                  Header       => Header);
               case Header.Kind is
                  when Spawn.Protocol.Shell_Request =>
                     declare
                        Wire_Request : Spawn.Protocol.Shell_Request_Type;
                        Result : Spawn_Manager_Processes.Execution_Result;
                     begin
                        Spawn.Protocol.Decode_Shell_Request
                          (Data         => Frame,
                           Active_Bound => Buffer_Size,
                           Request      => Wire_Request);
                        pragma Debug
                          (L.Log_File ("Shell request received:"));
                        pragma Debug
                          (L.Log_File ("- CMD  ["
                           & S (Wire_Request.Command) & "]"));
                        pragma Debug
                          (L.Log_File ("- DIR  ["
                           & S (Wire_Request.Directory) & "]"));
                        Result := Execute_Request
                          (Request =>
                             Spawn_Manager_Processes.Create_Shell_Request
                               (Command   => S (Wire_Request.Command),
                                Directory => S (Wire_Request.Directory),
                                Timeout   => Wire_Request.Timeout));
                        pragma Debug
                          (L.Log_File
                             ("Command result: "
                              & Spawn_Manager_Processes.Diagnostic (Result)));
                        Send_Reply (Result => To_Protocol_Result (Result));
                     end;
                  when Spawn.Protocol.Exec_Request =>
                     declare
                        Wire_Request : Spawn.Protocol.Exec_Request_Type;
                        Result : Spawn_Manager_Processes.Execution_Result;
                     begin
                        Spawn.Protocol.Decode_Exec_Request
                          (Data         => Frame,
                           Active_Bound => Buffer_Size,
                           Request      => Wire_Request);
                        pragma Debug
                          (L.Log_File ("Structured exec request received:"));
                        pragma Debug
                          (L.Log_File ("- EXE  ["
                           & S (Wire_Request.Executable) & "]"));
                        pragma Debug
                          (L.Log_File ("- ARGC ["
                           & Wire_Request.Arguments.Length'Image & "]"));
                        pragma Debug
                          (L.Log_File ("- ENVC ["
                           & Wire_Request.Environment.Length'Image & "]"));
                        Result := Execute_Request
                          (Request =>
                             Spawn_Manager_Processes.Create_Exec_Request
                               (Request => Wire_Request));
                        pragma Debug
                          (L.Log_File
                             ("Command result: "
                              & Spawn_Manager_Processes.Diagnostic (Result)));
                        Send_Reply (Result => To_Protocol_Result (Result));
                     end;
                  when Spawn.Protocol.Result_Message =>
                     raise Spawn.Protocol.Protocol_Error with
                       "request used result message kind";
               end case;
            end;

         exception
            when E : Spawn.Protocol.Request_Error =>
               pragma Debug (L.Log_File ("Request rejected:"));
               pragma Debug
                 (L.Log_File (Ada.Exceptions.Exception_Information (E)));
               Send_Reply
                 (Result =>
                    (Kind       => Spawn.Protocol.Request_Rejected,
                     Diagnostic => To_Unbounded_String
                       (Ada.Exceptions.Exception_Message (E))));
            when Spawn.Transport.Peer_Closed =>
               exit Main;
            when E : Spawn.Protocol.Protocol_Error
               | Spawn.Transport.Extra_Data
               | Spawn.Transport.Transport_Timeout =>
               pragma Debug (L.Log_File ("Protocol failure:"));
               pragma Debug
                 (L.Log_File (Ada.Exceptions.Exception_Information (E)));
               Send_Reply_Protocol_Failure
                 (Diagnostic => Ada.Exceptions.Exception_Message (E));
               exit Main;
            when E : others =>
               pragma Debug (L.Log_File ("Internal manager failure:"));
               pragma Debug
                 (L.Log_File (Ada.Exceptions.Exception_Information (E)));
               Send_Reply_Protocol_Failure
                 (Diagnostic => "internal manager failure");
               exit Main;
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
