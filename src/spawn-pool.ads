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

with Ada.Directories;
with Ada.Streams;

package Spawn.Pool is

   Mngr_Binary : constant String := "spawn_manager";
   --  Default spawn manager binary name/path.

   procedure Init (Manager_Count : Positive := 1);
   --  Init pool with given number of spawn managers.

   procedure Add_Manager
     (Binary_Cmd  : String := Mngr_Binary;
      Socket_Addr : String);
   --  Add new spawn manager to pool. Binary_Cmd specifies the command used to
   --  spawn a new manager, Socket_Addr designates the Unix domain socket path
   --  the manager will listen for requests.

   procedure Remove_Manager (Socket_Addr : String);
   --  Remove spawn manager with given socket address from pool.

   procedure Execute
     (Command   : String;
      Directory : String := Ada.Directories.Current_Directory);
   --  Execute command in given directory.

   procedure Cleanup;
   --  Cleanup spawn pool.

   Command_Failed    : exception;
   Manager_Not_Found : exception;

private

   function Send_Receive
     (Request : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array;
   --  Send given data as request to spawn manager. Return data of received
   --  reply.

end Spawn.Pool;
