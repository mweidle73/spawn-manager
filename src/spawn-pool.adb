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

with Ada.Containers.Ordered_Maps;
with Ada.Strings.Unbounded;
with Ada.Unchecked_Deallocation;

with GNAT.OS_Lib;
with GNAT.Expect;

with Anet.Sockets;

with Spawn.Types;
with Spawn.Logger;
with Spawn.Utils;

package body Spawn.Pool is

   Addr_Base : constant String := "/tmp/spawn_manager-";

   use Ada.Strings.Unbounded;

   package L renames Spawn.Logger;

   type Socket_Handle is access Anet.Sockets.Socket_Type;

   procedure Free is new Ada.Unchecked_Deallocation
     (Object => Anet.Sockets.Socket_Type,
      Name   => Socket_Handle);
   --  Free allocated socket memory.

   type Socket_Container is record
      Address   : Unbounded_String;
      Pid       : GNAT.Expect.Process_Descriptor;
      Handle    : Socket_Handle;
      Available : Boolean;
   end record;

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

      procedure Remove_Socket (Path : String);
      --  Remove socket with given path from socket store.

      procedure Cleanup;
      --  Cleanup socket store.
   private
      Data : SOMP.Map;
   end Sockets;

   -------------------------------------------------------------------------

   procedure Add_Manager
     (Binary_Cmd  : String := Mngr_Binary;
      Socket_Addr : String)
   is
      use type GNAT.OS_Lib.Process_Id;

      Args : GNAT.OS_Lib.Argument_List_Access;
      Pid  : GNAT.Expect.Process_Descriptor;
   begin
      Args := GNAT.OS_Lib.Argument_String_To_List
        (Arg_String => Binary_Cmd & " " & Socket_Addr);

      begin
         GNAT.Expect.Non_Blocking_Spawn
           (Descriptor  => Pid,
            Command     => Args (Args'First).all,
            Args        => Args (Args'First + 1 .. Args'Last),
            Buffer_Size => 0);

      exception
         when GNAT.Expect.Invalid_Process =>
            GNAT.OS_Lib.Free (Args);
            raise Command_Failed with "Unable to fork manager (using command '"
              & Mngr_Binary & "')";
      end;

      GNAT.OS_Lib.Free (Args);

      pragma Debug (L.Log ("Waiting for socket '" & Socket_Addr
        & "' to become available"));
      Utils.Wait_For_Socket (Path     => Socket_Addr,
                             Timespan => 3.0);

      declare
         Sock : constant Socket_Handle := new Anet.Sockets.Socket_Type;
      begin
         Sock.Create (Family => Anet.Sockets.Family_Unix,
                      Mode   => Anet.Sockets.Stream_Socket);
         Sock.Connect (Path => Socket_Addr);
         Sockets.Insert_Socket
           (S => (Address   => To_Unbounded_String (Socket_Addr),
                  Pid       => Pid,
                  Handle    => Sock,
                  Available => True));
         pragma Debug (L.Log ("Socket " & Socket_Addr & " ready"));
      end;
   end Add_Manager;

   -------------------------------------------------------------------------

   procedure Cleanup
   is
   begin
      Sockets.Cleanup;
   end Cleanup;

   -------------------------------------------------------------------------

   procedure Execute
     (Command   : String;
      Directory : String := Ada.Directories.Current_Directory)
   is
      Reply   : Types.Data_Type;
      Request : constant Types.Data_Type
        := (Command => To_Unbounded_String (Command),
            Dir     => To_Unbounded_String (Directory),
            others  => <>);
   begin
      pragma Debug (L.Log ("Executing command '" & Command & "'"));

      Reply := Types.Deserialize
        (Buffer => Send_Receive
           (Request => Types.Serialize
              (Data => Request)));

      if not Reply.Success then
         raise Command_Failed with "Command failed: '" & Command & "'";
      end if;
   end Execute;

   -------------------------------------------------------------------------

   procedure Init (Manager_Count : Positive := 1)
   is
   begin
      for M in 1 .. Manager_Count loop
         declare
            Addr : constant String := Addr_Base
              & Utils.Random_String (Len => 8);
         begin
            Add_Manager (Socket_Addr => Addr);
         end;
      end loop;
   end Init;

   -------------------------------------------------------------------------

   procedure Remove_Manager (Socket_Addr : String)
   is
   begin
      Sockets.Remove_Socket (Path => Socket_Addr);
   end Remove_Manager;

   -------------------------------------------------------------------------

   function Send_Receive
     (Request : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array
   is
      Cont : Socket_Container;
   begin
      Sockets.Get_Socket (S => Cont);
      pragma Debug (L.Log ("Sending request using socket "
        & To_String (Cont.Address)));

      Cont.Handle.Send (Item => Request);

      Receive_Reponse :
      declare
         Response : Ada.Streams.Stream_Element_Array (1 .. 4);
         Last_Idx : Ada.Streams.Stream_Element_Offset;
         Sender   : Anet.Sockets.Sender_Info_Type;
      begin
         Cont.Handle.Receive (Src  => Sender,
                              Item => Response,
                              Last => Last_Idx);
         Sockets.Release_Socket (C => Cont);

         return Response (Response'First .. Last_Idx);
      end Receive_Reponse;
   end Send_Receive;

   -------------------------------------------------------------------------

   protected body Sockets
   is
      -------------------------------------------------------------------------

      procedure Cleanup
      is
         S   : Socket_Container;
         Pos : SOMP.Cursor := Data.First;
      begin
         while SOMP.Has_Element (Position => Pos) loop
            S := SOMP.Element (Position => Pos);
            S.Handle.Close;
            Free (X => S.Handle);
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
            raise Command_Failed with
              "No free spawn manager available, increase the pool size";
         end if;

         pragma Debug (L.Log ("Found available socket "
           & To_String (S.Address)));
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
         pragma Debug (L.Log ("Socket " & To_String
           (SOMP.Element (Position => Pos).Address) & " released"));
      end Release_Socket;

      ----------------------------------------------------------------------

      procedure Remove_Socket (Path : String)
      is
         use type SOMP.Cursor;

         Pos : SOMP.Cursor := Data.Find (Key => To_Unbounded_String (Path));
         S   : Socket_Container;
      begin
         if Pos = SOMP.No_Element then
            raise Manager_Not_Found with "Unable to remove manager ["
              & Path & "] from pool";
         end if;

         S := SOMP.Element (Pos);
         S.Handle.Close;
         Free (X => S.Handle);
         Data.Delete (Position => Pos);
      end Remove_Socket;

   end Sockets;

end Spawn.Pool;
