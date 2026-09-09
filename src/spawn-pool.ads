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

with Ada.Directories;
with Ada.Streams;
with Ada.Unchecked_Deallocation;
with Ada.Strings.Unbounded;

with Anet.Sockets.Unix;

with GNAT.Expect;

with Spawn.Protocol;

package Spawn.Pool is

   use Ada.Strings.Unbounded;

   type Log_Procedure is access procedure (Msg : String);

   procedure No_Log (Msg : String) is null;
   --  Discard one optional pool diagnostic.

   procedure Init
     (Manager_Path   : String;
      Manager_Count  : Positive      := 1;
      Socket_Dir     : String        := "/tmp";
      Socket_Timeout : Duration      := 3.0;
      Buffer_Size    : Positive      := 8192;
      Log            : Log_Procedure := No_Log'Access);
   --  Start Manager_Count processes from the explicit absolute Manager_Path.
   --  Socket_Dir owns one randomized mode-0700 directory containing every
   --  manager socket. Socket_Timeout bounds each manager's startup.
   --  Buffer_Size is the active request and response frame bound and may not
   --  exceed the fixed protocol maximum. A relative Socket_Dir remains
   --  relative on the wire to protect the AF_UNIX length budget; Init
   --  separately captures its absolute spelling so later directory changes
   --  cannot break cleanup.

   procedure No_Pid_Setup (Pid : GNAT.Expect.Process_Descriptor) is null;
   --  Leave the selected long-lived manager in its current process context.

   procedure Execute
     (Command   : String;
      Directory : String  := Ada.Directories.Current_Directory;
      Timeout   : Integer := -1;
      Pid_Setup : access procedure
        (Pid : GNAT.Expect.Process_Descriptor) := No_Pid_Setup'Access);
   --  Execute Command as `/bin/bash -o pipefail -c` in Directory. Timeout is
   --  measured in milliseconds and -1 means unlimited. Pid_Setup receives the
   --  long-lived manager before it forks the shell. Raise Command_Failed for
   --  every result other than exit status zero.

   function Execute
     (Request   : Spawn.Protocol.Exec_Request_Type;
      Pid_Setup : access procedure
        (Pid : GNAT.Expect.Process_Descriptor) := No_Pid_Setup'Access)
      return Spawn.Protocol.Result_Type;
   --  Execute one structured request and return its exact termination result.
   --  Pid_Setup receives the selected long-lived manager before it forks the
   --  request child; concurrent calls acquire independent manager leases.

   procedure Execute_Checked
     (Request   : Spawn.Protocol.Exec_Request_Type;
      Pid_Setup : access procedure
        (Pid : GNAT.Expect.Process_Descriptor) := No_Pid_Setup'Access);
   --  Execute one structured request and raise unless it exits with status 0.

   procedure Cleanup;
   --  Stop new leases, cancel every manager, wait for active callers to leave
   --  the pool and remove all socket state. Cleanup cancels the complete pool.

   Pool_Error         : exception;
   Command_Failed     : exception;
   Connection_Refused : exception;

private

   type Socket_Handle is access Anet.Sockets.Unix.TCP_Socket_Type;

   type Socket_Container is record
      Address         : Unbounded_String;
      Cleanup_Address : Unbounded_String;
      Pid             : GNAT.Expect.Process_Descriptor;
      Socket          : Socket_Handle;
      Available       : Boolean;
   end record;

   L : Log_Procedure := null;
   --  Log procedure.

   Cmd_Buffer_Size : Ada.Streams.Stream_Element_Offset;
   --  Size of the command send/receive buffer and stream array.

   procedure Log_A_File (Filename : String);
   --  Log the contents of the specified file.

   type Delete_File_Procedure is access procedure (Filename : String);

   procedure Delete_Socket_File (Filename : String);
   --  Remove the given socket file.

   procedure Remove_Socket_File (Filename : String);
   --  Remove a manager socket without aborting cleanup of the remaining
   --  managers when unlink(2) fails.

   Socket_File_Delete : Delete_File_Procedure := Delete_Socket_File'Access;
   --  Socket removal operation. A named indirection keeps the cleanup error
   --  path deterministic for the child-package tests.

   procedure Free is new Ada.Unchecked_Deallocation
     (Object => Anet.Sockets.Unix.TCP_Socket_Type,
      Name   => Socket_Handle);
   --  Free allocated socket memory.

   procedure Connect_Retry_On_Refused
     (Socket : Socket_Handle;
      Path   : Anet.Sockets.Unix.Path_Type;
      Count  : Positive);
   --  Try to connect to socket. If the socket responds with connection
   --  refused, sleep one second and retry. This might happen if the manager
   --  created the socket but is not yet ready to accept connections.
   --  Raises custom Connection_Refused exception if socket refuses connection
   --  after Count tries.

end Spawn.Pool;
