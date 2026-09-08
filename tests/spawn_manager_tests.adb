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

with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;

with Anet.Sockets;
with Anet.Sockets.Unix;

with Spawn.Protocol;
with Spawn.Transport;

package body Spawn_Manager_Tests is

   use Ada.Strings.Unbounded;
   use Ahven;
   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_32;
   use type Spawn.Protocol.Result_Kind;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Spawn manager tests");
      T.Add_Test_Routine
        (Routine => Send_Receive'Access,
         Name    => "Send and receive data");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Send_Receive
   is
      Socket : Anet.Sockets.Unix.TCP_Socket_Type;

      function Receive_Result return Spawn.Protocol.Result_Type;
      --  Receive and decode one manager result.

      function Receive_Result return Spawn.Protocol.Result_Type
      is
         Data : constant Ada.Streams.Stream_Element_Array
           := Spawn.Transport.Receive_Frame
             (Descriptor            => Socket.Get_Socket,
              Active_Bound          => 8_192,
              First_Byte_Timeout_MS => 1_000);
         Result : Spawn.Protocol.Result_Type;
      begin
         Spawn.Protocol.Decode_Result
           (Data         => Data,
            Active_Bound => 8_192,
            Result       => Result);
         return Result;
      end Receive_Result;
   begin
      Socket.Init;

      delay 0.3;

      Socket.Connect (Path => "obj/spawn_manager_0");
      Socket.Set_Nonblocking_Mode;

      declare
         Request : constant Spawn.Protocol.Shell_Request_Type
           := (Command   => To_Unbounded_String ("/bin/true"),
               Directory => Null_Unbounded_String,
               Timeout   => -1);
         Length : constant Positive
           := Spawn.Protocol.Shell_Request_Frame_Length
             (Request      => Request,
              Active_Bound => 8_192);
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
         Result : Spawn.Protocol.Result_Type;
      begin
         Spawn.Protocol.Encode_Shell_Request
           (Request      => Request,
            Active_Bound => 8_192,
            Data         => Data);
         Data (Data'Last) := 16#fe#;
         Spawn.Transport.Send_Frame
           (Descriptor => Socket.Get_Socket,
            Data       => Data);
         Result := Receive_Result;
         Assert (Condition => Result.Kind = Spawn.Protocol.Request_Rejected,
                 Message   => "request rejection expected");
      end;

      declare
         Request : constant Spawn.Protocol.Shell_Request_Type
           := (Command   => To_Unbounded_String ("/bin/true"),
               Directory => Null_Unbounded_String,
               Timeout   => -1);
         Length : constant Positive
           := Spawn.Protocol.Shell_Request_Frame_Length
             (Request      => Request,
              Active_Bound => 8_192);
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
         Result : Spawn.Protocol.Result_Type;
      begin
         Spawn.Protocol.Encode_Shell_Request
           (Request      => Request,
            Active_Bound => 8_192,
            Data         => Data);
         Spawn.Transport.Send_Frame
           (Descriptor => Socket.Get_Socket,
            Data       => Data);
         Result := Receive_Result;
         Assert (Condition => Result.Kind = Spawn.Protocol.Exited,
                 Message   => "exit result expected");
         Assert (Condition => Result.Exit_Status = 0,
                 Message   => "zero exit status expected");
      end;

      declare
         Invalid : constant Ada.Streams.Stream_Element_Array (1 .. 12)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#02#, 16#00#, 16#01#,
               16#00#, 16#00#, 16#00#, 16#00#);
         Result : Spawn.Protocol.Result_Type;
      begin
         Socket.Send (Item => Invalid);
         Result := Receive_Result;
         Assert (Condition => Result.Kind = Spawn.Protocol.Protocol_Failed,
                 Message   => "protocol failure expected");
      end;

      Socket.Close;
   end Send_Receive;

end Spawn_Manager_Tests;
