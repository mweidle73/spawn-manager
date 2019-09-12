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

package Spawn.Pool is

   use Ada.Strings.Unbounded;

   type Log_Procedure is access procedure (Msg : String);

   procedure No_Log (Msg : String) is null;

   procedure Init
     (Manager_Count  : Positive      := 1;
      Socket_Dir     : String        := "/tmp";
      Socket_Timeout : Duration      := 3.0;
      Buffer_Size    : Positive      := 8192;
      Log            : Log_Procedure := No_Log'Access);
   --  Init pool with given number of spawn managers. The Socket_Dir argument
   --  specifies the directory used to store spawn_manager communication
   --  sockets and the optional log procedure will be used to log additional
   --  runtime information. The optional socket timeout argument defines the
   --  duration to wait for the appearance of each (1 .. Manager_Count)
   --  communication sockets. If a timeout occurs, an exception is raised.
   --  The Buffer_Size argument specifies the size of the command buffer used
   --  in the spawned managers to receive commands.

   procedure Execute
     (Command   : String;
      Directory : String  := Ada.Directories.Current_Directory;
      Timeout   : Integer := -1;
      Cgroup    : Unbounded_String := Null_Unbounded_String);
   --  Execute command in given directory. The Timeout parameter specifies the
   --  time in milliseconds after the command times out (the default is no
   --  timeout (-1)). If a timeout occurs, a Command_Failed exception is raised
   --  to indicate failure.

   procedure Cleanup;
   --  Cleanup spawn pool.

   Pool_Error         : exception;
   Command_Failed     : exception;
   Connection_Refused : exception;

private

   function Send_Receive
     (Request : Ada.Streams.Stream_Element_Array)
      return Ada.Streams.Stream_Element_Array;
   --  Send given data as request to spawn manager. Return data of received
   --  reply.

   L : Log_Procedure := null;
   --  Log procedure.

   Cmd_Buffer_Size : Ada.Streams.Stream_Element_Offset;
   --  Size of the command send/receive buffer and stream array.

   procedure Log_A_File (Filename : String);
   --  Log the contents of the specified file.

   type Socket_Handle is access Anet.Sockets.Unix.TCP_Socket_Type;

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
