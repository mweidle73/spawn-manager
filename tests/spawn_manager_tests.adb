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

with Anet.Sockets.Unix;
with Anet.Streams;

with Spawn.Types;

package body Spawn_Manager_Tests is

   use Ada.Strings.Unbounded;
   use Ahven;
   use Spawn;

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
      use Ada.Streams;

      Stream   : aliased Anet.Streams.Memory_Stream_Type (Max_Elements => 38);
      Socket   : Anet.Sockets.Unix.TCP_Socket_Type;
      Invalid1 : constant Stream_Element_Array (1 .. 9) := (others => 16#ac#);
      Invalid2 : constant Stream_Element_Array (1 .. 2) := (others => 234);
      Req      : constant Types.Data_Type
        := (Command => To_Unbounded_String ("/bin/true"),
            others  => <>);
   begin
      Socket.Init;

      delay 0.3;

      Socket.Connect (Path => "obj/spawn_manager_0");

      Socket.Send (Item => Invalid1);
      declare
         Data     : Stream_Element_Array (1 .. 128);
         Last_Idx : Stream_Element_Offset;
         Response : Types.Data_Type;
      begin
         Socket.Receive (Item => Data,
                         Last => Last_Idx);

         Stream.Set_Buffer (Buffer => Data (Data'First .. Last_Idx));
         Types.Data_Type'Read (Stream'Access, Response);
         Assert (Condition => not Response.Success,
                 Message   => "Failure expected (1)");
      end;

      Socket.Send (Item => Invalid2);
      declare
         Data     : Stream_Element_Array (1 .. 128);
         Last_Idx : Stream_Element_Offset;
         Response : Types.Data_Type;
      begin
         Socket.Receive (Item => Data,
                         Last => Last_Idx);

         Stream.Set_Buffer (Buffer => Data (Data'First .. Last_Idx));
         Types.Data_Type'Read (Stream'Access, Response);
         Assert (Condition => not Response.Success,
                 Message   => "Failure expected (2)");
      end;

      Stream.Clear;
      Types.Data_Type'Write (Stream'Access, Req);
      Socket.Send (Item => Stream.Get_Buffer);
      declare
         Data     : Stream_Element_Array (1 .. 128);
         Last_Idx : Stream_Element_Offset;
         Response : Types.Data_Type;
      begin
         Socket.Receive (Item => Data,
                         Last => Last_Idx);

         Stream.Set_Buffer (Buffer => Data (Data'First .. Last_Idx));
         Types.Data_Type'Read (Stream'Access, Response);
         Assert (Condition => Response.Success,
                 Message   => "Cmd not successful");
      end;

      Socket.Close;
   end Send_Receive;

end Spawn_Manager_Tests;
