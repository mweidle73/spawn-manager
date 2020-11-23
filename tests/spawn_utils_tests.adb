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

with Spawn.Utils;

package body Spawn_Utils_Tests is

   use Ahven;
   use Spawn.Utils;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Spawn utils tests");
      T.Add_Test_Routine
        (Routine => Locate_Executables'Access,
         Name    => "Locate executables in PATH");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Locate_Executables
   is
   begin
      Assert (Condition => Locate_Exec_On_Path (Name => "bash") = "/usr/bin/bash",
              Message   => "Unexpected path");

      begin
         declare
            Path : constant String := Locate_Exec_On_Path
              (Name => "nonexistent");
            pragma Unreferenced (Path);
         begin
            Fail (Message => "Exception expected");
         end;

      exception
         when Exec_Not_Found => null;
      end;
   end Locate_Executables;

end Spawn_Utils_Tests;
