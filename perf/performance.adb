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
with Ada.Directories;
with Ada.Real_Time;
with Ada.Strings;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;
with Ada.Text_IO;
with Interfaces;

with GNAT.OS_Lib;

with Spawn.Pool;
with Spawn.Protocol;

procedure Performance
is
   use type Ada.Real_Time.Time;
   use type Ada.Directories.File_Size;
   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_32;
   use type Spawn.Protocol.Result_Kind;

   Loops                 : constant := 1000;
   Output_Loops          : constant := 200;
   Large_Output_Loops    : constant := 50;
   Lifecycle_Loops       : constant := 25;
   Parallel_Loops        : constant := 100;
   Representative_Count : constant := 32;

   Manager_Path : constant String
     := Ada.Directories.Full_Name ("obj/spawn_manager");
   Fixture_Path : constant String
     := Ada.Directories.Full_Name ("obj/spawn_posix_tests");
   Stdout_Path : constant String
     := Ada.Directories.Full_Name ("obj/performance.stdout");
   Stderr_Path : constant String
     := Ada.Directories.Full_Name ("obj/performance.stderr");

   type Sample_Array is array (Positive range <>) of Duration;

   procedure Sort is new Ada.Containers.Generic_Array_Sort
     (Index_Type   => Positive,
      Element_Type => Duration,
      Array_Type   => Sample_Array);
   --  Order one arm's latency samples before percentile reporting.

   procedure Measure_Lifecycle;
   --  Measure one-manager pool initialization plus cleanup.

   procedure Measure_Manager (Command : String; Label : String);
   --  Measure one command through the current manager pool.

   procedure Measure_Output (Bytes : Positive; Samples : Positive);
   --  Measure independent stdout and stderr file output of the given size.

   procedure Measure_Parallel (Manager_Count : Positive);
   --  Measure structured throughput using one task per manager.

   procedure Measure_Structured
     (Request : Spawn.Protocol.Exec_Request_Type;
      Label   : String;
      Samples : Positive := Loops);
   --  Measure one structured request through the complete pool path.

   function New_Request (Executable : String)
      return Spawn.Protocol.Exec_Request_Type;
   --  Construct the common null-stream, empty-environment request.

   procedure Report (Label : String; Samples : in out Sample_Array);
   --  Report mean, median and p95 for one sorted sample arm.

   procedure Measure_Lifecycle
   is
      Samples : Sample_Array (1 .. Lifecycle_Loops);
      Start   : Ada.Real_Time.Time;
   begin
      Spawn.Pool.Cleanup;
      for Index in Samples'Range loop
         Start := Ada.Real_Time.Clock;
         Spawn.Pool.Init (Manager_Path => Manager_Path);
         Spawn.Pool.Cleanup;
         Samples (Index) := Ada.Real_Time.To_Duration
           (Ada.Real_Time.Clock - Start);
      end loop;
      Report (Label   => "one-manager startup and cleanup",
              Samples => Samples);
   end Measure_Lifecycle;

   -------------------------------------------------------------------------

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

   procedure Measure_Output (Bytes : Positive; Samples : Positive)
   is
      use Ada.Strings.Unbounded;

      Byte_Count : constant String := Ada.Strings.Fixed.Trim
        (Source => Positive'Image (Bytes),
         Side   => Ada.Strings.Both);
      Request : Spawn.Protocol.Exec_Request_Type := New_Request (Fixture_Path);

      procedure Delete_Output;
      --  Remove files retained by the final benchmark request.

      procedure Delete_Output
      is
      begin
         if Ada.Directories.Exists (Stdout_Path) then
            Ada.Directories.Delete_File (Stdout_Path);
         end if;
         if Ada.Directories.Exists (Stderr_Path) then
            Ada.Directories.Delete_File (Stderr_Path);
         end if;
      end Delete_Output;
   begin
      Delete_Output;
      Request.Arguments.Append ("fixture");
      Request.Arguments.Append ("output");
      Request.Arguments.Append (Byte_Count);
      Request.Directory := To_Unbounded_String
        (Ada.Directories.Current_Directory);
      Request.Standard_Output :=
        (Mode => Spawn.Protocol.Truncate_File,
         Path => To_Unbounded_String (Stdout_Path));
      Request.Standard_Error :=
        (Mode => Spawn.Protocol.Truncate_File,
         Path => To_Unbounded_String (Stderr_Path));

      Measure_Structured
        (Request => Request,
         Label   => "manager structured split output " & Byte_Count
           & " bytes per stream",
         Samples => Samples);
      if Ada.Directories.Size (Stdout_Path)
           /= Ada.Directories.File_Size (Bytes)
        or else Ada.Directories.Size (Stderr_Path)
           /= Ada.Directories.File_Size (Bytes)
      then
         raise Program_Error with "structured output size changed";
      end if;
      Delete_Output;

   exception
      when others =>
         Delete_Output;
         raise;
   end Measure_Output;

   -------------------------------------------------------------------------

   procedure Measure_Parallel (Manager_Count : Positive)
   is
      protected Failures is
         procedure Mark;
         --  Record that one parallel runner observed a failed request.

         function Seen return Boolean;
         --  Return whether any parallel runner observed a failed request.
      private
         Failed : Boolean := False;
      end Failures;

      protected body Failures is
         procedure Mark
         is
         begin
            Failed := True;
         end Mark;

         function Seen return Boolean
         is (Failed);
      end Failures;

      task type Runner is
         entry Start;
         entry Finish;
      end Runner;

      task body Runner
      is
         Request : constant Spawn.Protocol.Exec_Request_Type
           := New_Request ("/bin/true");
         Result : Spawn.Protocol.Result_Type;
      begin
         accept Start;
         begin
            for Index in 1 .. Parallel_Loops loop
               Result := Spawn.Pool.Execute (Request => Request);
               if Result.Kind /= Spawn.Protocol.Exited
                 or else Result.Exit_Status /= 0
               then
                  Failures.Mark;
                  exit;
               end if;
            end loop;
         exception
            when others =>
               Failures.Mark;
         end;
         accept Finish;
      end Runner;

      Workers : array (1 .. Manager_Count) of Runner;
      Start   : Ada.Real_Time.Time;
      Elapsed : Duration;
      Total   : constant Positive := Manager_Count * Parallel_Loops;
   begin
      Spawn.Pool.Init
        (Manager_Path  => Manager_Path,
         Manager_Count => Manager_Count);
      Start := Ada.Real_Time.Clock;
      for Worker of Workers loop
         Worker.Start;
      end loop;
      for Worker of Workers loop
         Worker.Finish;
      end loop;
      Elapsed := Ada.Real_Time.To_Duration (Ada.Real_Time.Clock - Start);
      Spawn.Pool.Cleanup;

      if Failures.Seen then
         raise Program_Error with "parallel structured benchmark failed";
      end if;
      Ada.Text_IO.Put_Line
        ("* manager structured parallel" & Manager_Count'Image
         & " managers requests=" & Total'Image
         & " elapsed=" & Duration'Image (Elapsed)
         & " throughput=" & Long_Float'Image
           (Long_Float (Total) / Long_Float (Elapsed)) & " requests/s");

   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Measure_Parallel;

   -------------------------------------------------------------------------

   procedure Measure_Structured
     (Request : Spawn.Protocol.Exec_Request_Type;
      Label   : String;
      Samples : Positive := Loops)
   is
      Result  : Spawn.Protocol.Result_Type;
      Timings : Sample_Array (1 .. Samples);
      Start   : Ada.Real_Time.Time;
   begin
      for Index in Timings'Range loop
         Start := Ada.Real_Time.Clock;
         Result := Spawn.Pool.Execute (Request => Request);
         if Result.Kind /= Spawn.Protocol.Exited
           or else Result.Exit_Status /= 0
         then
            raise Program_Error with "structured benchmark request failed";
         end if;
         Timings (Index) := Ada.Real_Time.To_Duration
           (Ada.Real_Time.Clock - Start);
      end loop;
      Report (Label => Label, Samples => Timings);
   end Measure_Structured;

   -------------------------------------------------------------------------

   function New_Request (Executable : String)
      return Spawn.Protocol.Exec_Request_Type
   is
      use Ada.Strings.Unbounded;
   begin
      return
        (Executable      => To_Unbounded_String (Executable),
         Arguments       => Spawn.Protocol.String_Vectors.Empty_Vector,
         Environment     => Spawn.Protocol.Environment_Vectors.Empty_Vector,
         Directory       => To_Unbounded_String ("/"),
         Standard_Output => (Mode => Spawn.Protocol.Null_Stream),
         Standard_Error  => (Mode => Spawn.Protocol.Null_Stream),
         Timeout         => -1);
   end New_Request;

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
   Spawn.Pool.Init (Manager_Path => Manager_Path);

   Ada.Text_IO.Put_Line ("* Samples per arm:" & Loops'Image);
   Measure_Manager (Command => "true", Label => "manager shell builtin true");
   Measure_Manager
     (Command => "/bin/true",
      Label   => "manager shell /bin/true");

   declare
      use Ada.Strings.Unbounded;

      Basic          : constant Spawn.Protocol.Exec_Request_Type
        := New_Request ("/bin/true");
      Representative : Spawn.Protocol.Exec_Request_Type
        := New_Request ("/bin/true");
   begin
      for Index in 1 .. Representative_Count loop
         declare
            Suffix : constant String := Ada.Strings.Fixed.Trim
              (Source => Positive'Image (Index),
               Side   => Ada.Strings.Both);
         begin
            Representative.Arguments.Append
              ("representative argument " & Suffix);
            Representative.Environment.Append
              ((Name  => To_Unbounded_String ("PERF_VALUE_" & Suffix),
                Value => To_Unbounded_String
                  ("representative environment value " & Suffix)));
         end;
      end loop;

      Measure_Structured
        (Request => Basic,
         Label   => "manager structured /bin/true");
      Ada.Text_IO.Put_Line
        ("* representative structured frame bytes:"
         & Positive'Image (Spawn.Protocol.Exec_Request_Frame_Length
           (Request      => Representative,
            Active_Bound => Spawn.Protocol.Maximum_Frame_Size)));
      Measure_Structured
        (Request => Representative,
         Label   => "manager structured 32 argv and environment entries");
      Measure_Output (Bytes => 64, Samples => Output_Loops);
      Measure_Output (Bytes => 64 * 1024, Samples => Large_Output_Loops);
   end;

   declare
      Args    : GNAT.OS_Lib.Argument_List (1 .. 4);
      Samples : Sample_Array (1 .. Loops);
      Start   : Ada.Real_Time.Time;
      Status  : Boolean;
   begin
      Args (1) := new String'("-o");
      Args (2) := new String'("pipefail");
      Args (3) := new String'("-c");
      Args (4) := new String'("true");

      for Index in Samples'Range loop
         Start := Ada.Real_Time.Clock;
         GNAT.OS_Lib.Spawn
           (Program_Name => "/bin/bash",
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
      Report (Label => "direct GNAT bash true", Samples => Samples);
   end;

   Spawn.Pool.Cleanup;
   Measure_Lifecycle;
   declare
      Manager_Counts : constant array (Positive range 1 .. 4) of Positive
        := (1, 2, 4, 8);
   begin
      for Manager_Count of Manager_Counts loop
         Measure_Parallel (Manager_Count => Manager_Count);
      end loop;
   end;
end Performance;
