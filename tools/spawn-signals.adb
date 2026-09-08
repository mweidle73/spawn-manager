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

with GNAT.OS_Lib;

with Spawn.Logger;

package body Spawn.Signals is

   package L renames Spawn.Logger;

   procedure Terminate_Current
     with Import,
          Convention    => C,
          External_Name => "spawn_posix_terminate_current";
   --  Kill the active request group through the async-signal-safe C boundary.

   -------------------------------------------------------------------------

   protected body Exit_Handler_Type
   is
      ----------------------------------------------------------------------

      procedure Handle_Signal
      is
      begin
         pragma Debug (L.Log_File ("Signal received - shutting down"));
         Socket_L.Close;
         Socket_C.Close;
         if Running then
            pragma Debug
              (L.Log_File ("Active request still running, terminating group"));
            Terminate_Current;
         end if;
         GNAT.OS_Lib.OS_Exit (Status => Integer (Ada.Command_Line.Success));
      end Handle_Signal;

      ----------------------------------------------------------------------

      procedure Set_Running
      is
      begin
         Running := True;
      end Set_Running;

      ----------------------------------------------------------------------

      procedure Stopped
      is
      begin
         Running := False;
      end Stopped;

   end Exit_Handler_Type;

end Spawn.Signals;
