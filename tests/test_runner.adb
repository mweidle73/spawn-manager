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

with Ahven.Text_Runner;
with Ahven.Framework;

with Spawn.Utils;

with Spawn_Utils_Tests;
with Spawn_Manager_Tests;

with Spawn.Pool.Tests;

procedure Test_Runner is
   use Ahven.Framework;

   S : constant Test_Suite_Access
     := Create_Suite (Suite_Name => "IPC/Spawn tests");
begin
   Spawn.Utils.Expand_Search_Path (Cmd_Path => "obj/spawn_manager");

   Add_Test (Suite => S.all,
             T     => new Spawn_Utils_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Spawn_Manager_Tests.Testcase);
   Add_Test (Suite => S.all,
             T     => new Spawn.Pool.Tests.Testcase);

   Ahven.Text_Runner.Run (Suite => S);
   Release_Suite (T => S);

end Test_Runner;
