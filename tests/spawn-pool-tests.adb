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

with Ada.Text_IO;
with Ada.Exceptions;
with Ada.Directories;
with Ada.Real_Time;
with Ada.Strings.Unbounded;

with Anet.Util;

with Spawn.Pool;

package body Spawn.Pool.Tests is

   use Ahven;

   task type Executor is
      entry Call;
      entry Done (Success : out Boolean);
   end Executor;
   --  Task used in parallel tests.

   task body Executor is
      Got_Exception : Boolean := False;
   begin
      accept Call;

      begin
         Spawn.Pool.Execute (Command => "/bin/true");

      exception
         when E : others =>
            Ada.Text_IO.Put_Line
              (Ada.Exceptions.Exception_Information (X => E));
            Got_Exception := True;
      end;

      accept Done (Success : out Boolean) do
         Success := not Got_Exception;
      end Done;
   end Executor;

   Test_Buffer : Ada.Strings.Unbounded.Unbounded_String;

   procedure Test_Log (Msg : String);
   --  Append message to test buffer.

   Test_Log_Exception : exception;

   procedure Test_Log_Error (Msg : String);
   --  Just raises a test exception.

   -------------------------------------------------------------------------

   procedure Command_Timeout
   is
      use Ada.Real_Time;

      Start : Time;
      Span  : Time_Span := To_Time_Span (D => 100.0);
   begin
      Spawn.Pool.Init (Log => Ada.Text_IO.Put_Line'Access);

      begin
         Start := Clock;

         --  Command would run for 60 seconds but it should timeout after 50
         --  milliseconds.

         Spawn.Pool.Execute (Command => "/bin/sleep 60",
                             Timeout => 50);
         Fail (Message => "Failure expected");

      exception
         when Spawn.Pool.Command_Failed => Span := Clock - Start;
      end;

      Spawn.Pool.Cleanup;

      Assert (Condition => Span >= Milliseconds (MS => 50),
              Message   => "Timeout not >= 50ms");

      --  Take heavy system load into account; allow up to 1s as upper
      --  threshold

      Assert (Condition => Span < Seconds (S => 1),
              Message   => "Timeout not < 1s");

   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Command_Timeout;

   -------------------------------------------------------------------------

   procedure Connect_Retry_On_Refused
   is
      S : Socket_Handle
        := new Anet.Sockets.Unix.TCP_Socket_Type;
      P : constant Anet.Sockets.Unix.Path_Type
        := Anet.Sockets.Unix.Path_Type
          ("/tmp/spawn.retry-" & Anet.Util.Random_String (Len => 12));
   begin

      --  Positive test, calls Connect_Retry_On_Refused on 'real' manager.

      Spawn.Pool.Init (Log => Ada.Text_IO.Put_Line'Access);

      --  Negative test.

      S.Init;

      --  Socket error, but not connection refused.

      begin
         Connect_Retry_On_Refused (Socket => S,
                                   Path   => P,
                                   Count  => 2);
         Fail (Message => "Exception expected");

      exception
         when Anet.Sockets.Socket_Error => null;
      end;

      S.Bind (Path => P);

      --  Connection refused error.

      begin
         Connect_Retry_On_Refused (Socket => S,
                                   Path   => P,
                                   Count  => 2);
         Fail (Message => "Exception expected");

      exception
         when Connection_Refused => null;
      end;

      Free (X => S);
      Spawn.Pool.Cleanup;

   exception
      when others =>
         Free (X => S);
         Spawn.Pool.Cleanup;
         raise;
   end Connect_Retry_On_Refused;

   -------------------------------------------------------------------------

   procedure Execute_Bin_False
   is
   begin
      Spawn.Pool.Init (Log => Ada.Text_IO.Put_Line'Access);
      Spawn.Pool.Execute (Command => "/bin/false");
      Spawn.Pool.Cleanup;
      Fail (Message => "Exception expected");

   exception
      when Spawn.Pool.Command_Failed =>
         Spawn.Pool.Cleanup;
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Execute_Bin_False;

   -------------------------------------------------------------------------

   procedure Execute_Bin_True
   is
   begin
      Spawn.Pool.Init (Log => Ada.Text_IO.Put_Line'Access);
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;

   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Execute_Bin_True;

   -------------------------------------------------------------------------

   procedure Execute_Complex_Command
   is
      File : constant String := "obj/tmp.dat";
      Cmd  : constant String := "dd if=/dev/zero bs=1 count=1 of=" & File
        & " > /dev/null 2>&1";
   begin
      Spawn.Pool.Init (Log => Ada.Text_IO.Put_Line'Access);
      Spawn.Pool.Execute (Command => Cmd);
      Spawn.Pool.Cleanup;

      Assert (Condition => Ada.Directories.Exists (Name => File),
              Message   => "File not found: " & File);
      Ada.Directories.Delete_File (Name => File);

   exception
      when others =>
         Spawn.Pool.Cleanup;
         Ada.Directories.Delete_File (Name => File);
         raise;
   end Execute_Complex_Command;

   -------------------------------------------------------------------------

   procedure Execute_Nonexistent
   is
   begin
      Spawn.Pool.Init (Log => Ada.Text_IO.Put_Line'Access);

      begin
         Spawn.Pool.Execute (Command => "nonexistent/binary");
         Spawn.Pool.Cleanup;
         Fail (Message => "Exception expected");

      exception
         when Spawn.Pool.Command_Failed => null;
      end;

      --  Check if manager is still responding to requests.

      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;

   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Execute_Nonexistent;

   -------------------------------------------------------------------------

   procedure Execute_Nonterminating_Command
   is
      Got_Exception : Boolean := False;

      task Executor
      is
         entry Start;
      end Executor;

      task body Executor
      is
      begin
         accept Start;
         Spawn.Pool.Execute ("/bin/sleep 10000");

      exception
         when Spawn.Pool.Command_Failed => Got_Exception := True;
         when others                    => null;
      end Executor;

   begin
      Spawn.Pool.Init (Log => Ada.Text_IO.Put_Line'Access);
      Executor.Start;

      delay 0.3;
      Spawn.Pool.Cleanup;

      if not Executor'Terminated then
         abort Executor;
      end if;

      Assert (Condition => Got_Exception,
              Message   => "Exception expected");

   exception
      when others =>
         Spawn.Pool.Cleanup;
         if not Executor'Terminated then
            abort Executor;
         end if;
   end Execute_Nonterminating_Command;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Spawn pool tests");
      T.Add_Test_Routine
        (Routine => Execute_Bin_True'Access,
         Name    => "Execute /bin/true");
      T.Add_Test_Routine
        (Routine => Execute_Bin_False'Access,
         Name    => "Execute /bin/false");
      T.Add_Test_Routine
        (Routine => Execute_Nonexistent'Access,
         Name    => "Execute nonexistent command");
      T.Add_Test_Routine
        (Routine => Execute_Complex_Command'Access,
         Name    => "Execute complex command");
      T.Add_Test_Routine
        (Routine => Execute_Nonterminating_Command'Access,
         Name    => "Execute non-terminating command");
      T.Add_Test_Routine
        (Routine => Parallel_Execution'Access,
         Name    => "Parallel execution");
      T.Add_Test_Routine
        (Routine => Pool_Depleted'Access,
         Name    => "Pool depleted");
      T.Add_Test_Routine
        (Routine => Command_Timeout'Access,
         Name    => "Command timeout");
      T.Add_Test_Routine
        (Routine => Invalid_Socket_Directory'Access,
         Name    => "Invalid socket directory");
      T.Add_Test_Routine
        (Routine => Invalid_Socket_Path'Access,
         Name    => "Invalid socket path");
      T.Add_Test_Routine
        (Routine => Log_A_File'Access,
         Name    => "Log file contents");
      T.Add_Test_Routine
        (Routine => Connect_Retry_On_Refused'Access,
         Name    => "Retry connect on connection refused");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Invalid_Socket_Directory
   is
   begin
      Spawn.Pool.Init (Socket_Dir => "/nonexistent/nonexistent",
                       Log        => Ada.Text_IO.Put_Line'Access);

   exception
      when Spawn.Pool.Pool_Error => null;
   end Invalid_Socket_Directory;

   -------------------------------------------------------------------------

   procedure Invalid_Socket_Path
   is
      Dir : constant String := "/tmp/" & Anet.Util.Random_String (Len => 128);
   begin
      Ada.Directories.Create_Directory
        (New_Directory => Dir);

      Spawn.Pool.Init (Socket_Dir => Dir,
                       Log        => Ada.Text_IO.Put_Line'Access);

   exception
      when Spawn.Pool.Pool_Error => null;
   end Invalid_Socket_Path;

   -------------------------------------------------------------------------

   procedure Log_A_File
   is
      use Ada.Strings.Unbounded;

      Lf : constant String := "data/log_contents";

      Ref_Buffer : constant String :=
        Lf & ": this is a test" & ASCII.LF &
        Lf & ": log file" & ASCII.LF;
   begin
      L := Test_Log'Access;
      Log_A_File (Filename => Lf);
      Assert (Condition => Test_Buffer = Ref_Buffer,
              Message   => "Buffer mismatch: '"
              & To_String (Test_Buffer) & "'");

      begin
         L := Test_Log_Error'Access;
         Log_A_File (Filename => Lf);
         Fail (Message => "Exception expected");

      exception
         when Test_Log_Exception => null;
      end;

      L := null;

   exception
      when others =>
         L := null;
         raise;
   end Log_A_File;

   -------------------------------------------------------------------------

   procedure Parallel_Execution
   is
      Task_Array : array (1 .. 4) of Executor;
      Result     : Boolean := True;
   begin
      Spawn.Pool.Init (Manager_Count => 4,
                       Log           => Ada.Text_IO.Put_Line'Access);
      for T in Task_Array'Range loop
         Task_Array (T).Call;
      end loop;

      for T in Task_Array'Range loop
         declare
            Status : Boolean;
         begin
            Task_Array (T).Done (Success => Status);
            Result := Result and Status;
         end;
      end loop;

      Spawn.Pool.Cleanup;

      Assert (Condition => Result,
              Message   => "Parallel execution failed");

   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Parallel_Execution;

   -------------------------------------------------------------------------

   procedure Pool_Depleted
   is
      Task_Array : array (1 .. 8) of Executor;
      Result     : Boolean := True;
   begin
      Spawn.Pool.Init (Manager_Count => 4,
                       Log           => Ada.Text_IO.Put_Line'Access);

      for T in Task_Array'Range loop
         Task_Array (T).Call;
      end loop;

      for T in Task_Array'Range loop
         declare
            Temp : Boolean;
         begin
            Task_Array (T).Done (Success => Temp);

            --  One should fail (pool depleted).

            Result := Result and Temp;
         end;
      end loop;

      Spawn.Pool.Cleanup;
      Assert (Condition => not Result,
              Message   => "No call failed");

   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Pool_Depleted;

   -------------------------------------------------------------------------

   procedure Test_Log (Msg : String)
   is
      use type Ada.Strings.Unbounded.Unbounded_String;
   begin
      Test_Buffer := Test_Buffer & Msg & ASCII.LF;
   end Test_Log;

   -------------------------------------------------------------------------

   procedure Test_Log_Error (Msg : String)
   is
   begin
      raise Test_Log_Exception;
   end Test_Log_Error;

end Spawn.Pool.Tests;
