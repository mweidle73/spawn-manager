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

with Ada.Interrupts.Names;

with Anet.Sockets.Unix;

package Spawn.Signals is

   protected type Exit_Handler_Type
     (Socket_L : access Anet.Sockets.Unix.TCP_Socket_Type;
      Socket_C : access Anet.Sockets.Unix.TCP_Socket_Type)
   is
      procedure Set_Running;
      --  Indicate that the POSIX core owns an active request group which must
      --  be terminated before exiting to the OS.

      procedure Stopped;
      --  Indicate that no child is currently running.

   private
      procedure Handle_Signal;
      --  Close manager sockets, terminate any active group and exit promptly.

      pragma Attach_Handler (Handle_Signal, Ada.Interrupts.Names.SIGINT);
      pragma Attach_Handler (Handle_Signal, Ada.Interrupts.Names.SIGTERM);

      Running : Boolean := False;
   end Exit_Handler_Type;
   --  Handler used to perform cleanup and exit to OS on SIGTERM and SIGINT
   --  signals.

end Spawn.Signals;
