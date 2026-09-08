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

with Ada.Containers.Generic_Array_Sort;
with Ada.Real_Time;
with Ada.Text_IO;

with GNAT.OS_Lib;

with Spawn.Pool;
with Spawn.Utils;

procedure Performance
is
   use type Ada.Real_Time.Time;

   Loops : constant := 1000;

   type Sample_Array is array (Positive range <>) of Duration;

   procedure Sort is new Ada.Containers.Generic_Array_Sort
     (Index_Type   => Positive,
      Element_Type => Duration,
      Array_Type   => Sample_Array);

   procedure Measure_Manager (Command : String; Label : String);
   --  Measure one command through the current manager pool.

   procedure Report (Label : String; Samples : in out Sample_Array);
   --  Report mean, median and p95 for one sorted sample arm.

   procedure Measure_Manager (Command : String; Label : String)
   is
      Samples : Sample_Array (1 .. Loops);
      Start   : Ada.Real_Time.Time;
   begin
      for Index in Samples'Range loop
         Start := Ada.Real_Time.Clock;
         Spawn.Pool.Execute (Command => Command);
         Samples (Index) := Ada.Real_Time.To_Duration
           (Ada.Real_Time.Clock - Start);
      end loop;
      Report (Label => Label, Samples => Samples);
   end Measure_Manager;

   -------------------------------------------------------------------------

   procedure Report (Label : String; Samples : in out Sample_Array)
   is
      Total     : Duration := 0.0;
      P95_Index : constant Positive
        := Positive ((Samples'Length * 95 + 99) / 100);
   begin
      for Sample of Samples loop
         Total := Total + Sample;
      end loop;
      Sort (Samples);
      Ada.Text_IO.Put_Line
        ("* " & Label & " mean=" & Duration'Image (Total / Samples'Length)
         & " median=" & Duration'Image
           (Samples (Samples'First + Samples'Length / 2))
         & " p95=" & Duration'Image
           (Samples (Samples'First + P95_Index - 1)));
   end Report;
begin
   Spawn.Utils.Expand_Search_Path (Cmd_Path => "obj/spawn_manager");
   Spawn.Pool.Init;

   Ada.Text_IO.Put_Line ("* Samples per arm:" & Loops'Image);
   Measure_Manager (Command => "true", Label => "manager shell builtin true");
   Measure_Manager
     (Command => "/bin/true",
      Label   => "manager shell /bin/true");

   declare
      Args    : GNAT.OS_Lib.Argument_List (1 .. 5);
      Wrapper : constant String := Spawn.Utils.Locate_Exec_On_Path
        (Name => "spawn_wrapper");
      Samples : Sample_Array (1 .. Loops);
      Start   : Ada.Real_Time.Time;
      Status  : Boolean;
   begin
      Args (1) := new String'("/bin/bash");
      Args (2) := new String'("-o");
      Args (3) := new String'("pipefail");
      Args (4) := new String'("-c");
      Args (5) := new String'("true");

      for Index in Samples'Range loop
         Start := Ada.Real_Time.Clock;
         GNAT.OS_Lib.Spawn
           (Program_Name => Wrapper,
            Args         => Args,
            Success      => Status);
         Samples (Index) := Ada.Real_Time.To_Duration
           (Ada.Real_Time.Clock - Start);
         if not Status then
            raise Program_Error with "direct GNAT spawn failed";
         end if;
      end loop;

      for A in Args'Range loop
         GNAT.OS_Lib.Free (X => Args (A));
      end loop;
      Report (Label => "direct GNAT wrapper/bash true", Samples => Samples);
   end;

   Spawn.Pool.Cleanup;
end Performance;
