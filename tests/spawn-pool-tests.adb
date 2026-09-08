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
with Ada.Environment_Variables;
with Ada.Real_Time;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded;

with Interfaces.C;

with Anet.OS;
with Anet.Util;

with GNAT.Expect;

package body Spawn.Pool.Tests is

   use Ahven;
   use type Interfaces.C.int;

   function Block_Test_Signal return Interfaces.C.int
     with Import,
          Convention    => C,
          External_Name => "spawn_test_block_signal";
   --  Save the caller mask and block one test signal before manager startup.

   function Restore_Test_Signal_Mask return Interfaces.C.int
     with Import,
          Convention    => C,
          External_Name => "spawn_test_restore_signal_mask";
   --  Restore the signal mask saved by Block_Test_Signal.

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

   procedure Raise_Delete_Error (Filename : String);
   --  Raise a deterministic socket deletion error.

   -------------------------------------------------------------------------

   procedure Cleanup_Relative_Socket
   is
      use Ada.Directories;

      Dir               : constant String := "obj/relative-socket-"
        & Anet.Util.Random_String (Len => 8);
      Log_Prefix        : constant String := "Forked manager ";
      Socket_Path       : Unbounded_String;
      Original_Dir      : constant String := Current_Directory;
      Initialized       : Boolean := False;
      Directory_Changed : Boolean := False;

      procedure Remove_Test_Directory;
      procedure Remove_Test_Directory
      is
      begin
         if Exists (Name => Dir) then
            Delete_Tree (Directory => Dir);
         end if;
      end Remove_Test_Directory;
   begin
      Create_Directory (New_Directory => Dir);
      Test_Buffer := Null_Unbounded_String;
      Spawn.Pool.Init (Socket_Dir => Dir,
                       Log        => Test_Log'Access);
      Initialized := True;

      declare
         Log_Data      : constant String := To_String (Test_Buffer);
         Prefix_First  : Natural;
         Address_First : Natural;
         Newline       : Natural;
      begin
         Prefix_First := Ada.Strings.Fixed.Index
           (Source  => Log_Data,
            Pattern => Log_Prefix);
         Assert (Condition => Prefix_First > 0,
                 Message   => "Manager socket address not logged");
         Address_First := Prefix_First + Log_Prefix'Length;
         Newline := Ada.Strings.Fixed.Index
           (Source  => Log_Data,
            Pattern => (1 => ASCII.LF),
            From    => Address_First);
         Assert (Condition => Newline > Address_First,
                 Message   => "Manager socket address not terminated");
         Socket_Path := To_Unbounded_String
           (Log_Data (Address_First .. Newline - 1));
      end;

      --  The manager changes its cwd for the command. The parent then changes
      --  its cwd before cleanup. A relative socket path must still be removed
      --  from the directory where it was bound during Init.
      Spawn.Pool.Execute (Command   => "/bin/true",
                          Directory => "/tmp");
      Set_Directory (Directory => "/tmp");
      Directory_Changed := True;
      Spawn.Pool.Cleanup;
      Initialized := False;
      Set_Directory (Directory => Original_Dir);
      Directory_Changed := False;

      begin
         Anet.OS.Delete_File
           (Filename       => To_String (Socket_Path),
            Ignore_Missing => False);
         Fail (Message => "Relative manager socket was not removed: "
               & To_String (Socket_Path));
      exception
         when Anet.OS.IO_Error => null;
      end;
      Test_Buffer := Null_Unbounded_String;
      Remove_Test_Directory;

   exception
      when others =>
         Test_Buffer := Null_Unbounded_String;
         if Directory_Changed then
            Set_Directory (Directory => Original_Dir);
            Directory_Changed := False;
         end if;
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         Remove_Test_Directory;
         raise;
   end Cleanup_Relative_Socket;

   -------------------------------------------------------------------------

   procedure Cleanup_Socket_After_Delete_Error
   is
      use Ada.Directories;

      Dir : constant String := "obj/delete-error-"
        & Anet.Util.Random_String (Len => 8);
      Error_Prefix : constant String := "Unable to remove manager socket '"
        & Current_Directory & "/" & Dir & "/";

      Initialized : Boolean := False;

      procedure Remove_Test_Directory;
      procedure Remove_Test_Directory
      is
      begin
         if Exists (Name => Dir) then
            Delete_Tree (Directory => Dir);
         end if;
      end Remove_Test_Directory;
   begin
      Create_Directory (New_Directory => Dir);
      Test_Buffer := Null_Unbounded_String;
      Spawn.Pool.Init (Manager_Count => 2,
                       Socket_Dir    => Dir,
                       Log           => Test_Log'Access);
      Initialized := True;

      Socket_File_Delete := Raise_Delete_Error'Access;

      Spawn.Pool.Cleanup;
      Initialized := False;
      Socket_File_Delete := Delete_Socket_File'Access;

      Assert
        (Condition => Ada.Strings.Fixed.Count
           (Source  => To_String (Test_Buffer),
            Pattern => Error_Prefix) = 2,
         Message   => "Cleanup did not report both socket delete errors");

      Test_Buffer := Null_Unbounded_String;
      Spawn.Pool.Cleanup;
      Assert (Condition => Length (Test_Buffer) = 0,
              Message   => "Socket store was not cleared after delete errors");

      Remove_Test_Directory;

   exception
      when others =>
         Socket_File_Delete := Delete_Socket_File'Access;
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         Test_Buffer := Null_Unbounded_String;
         Remove_Test_Directory;
         raise;
   end Cleanup_Socket_After_Delete_Error;

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
      S_Server : Anet.Sockets.Unix.TCP_Socket_Type;
      S_Client : Socket_Handle
        := new Anet.Sockets.Unix.TCP_Socket_Type;
      Path     : constant Anet.Sockets.Unix.Path_Type
        := Anet.Sockets.Unix.Path_Type
          ("/tmp/spawn.retry-" & Anet.Util.Random_String (Len => 12));

      procedure Cleanup;
      procedure Cleanup
      is
      begin
         S_Client.Close;
         S_Server.Close;
         Free (X => S_Client);
         Spawn.Pool.Cleanup;
         L := null;
      end Cleanup;
   begin
      L := Ada.Text_IO.Put_Line'Access;

      S_Server.Init;
      S_Client.Init;

      --  Socket error, but not connection refused.

      begin
         Connect_Retry_On_Refused (Socket => S_Client,
                                   Path   => Path,
                                   Count  => 2);
         Fail (Message => "Exception expected");

      exception
         when Anet.Socket_Error => null;
      end;

      S_Server.Bind (Path => Path);

      --  Connection refused error.

      begin
         Connect_Retry_On_Refused (Socket => S_Client,
                                   Path   => Path,
                                   Count  => 2);
         Fail (Message => "Exception expected");

      exception
         when Connection_Refused => null;
      end;

      --  Reconnect succesful.

      declare
         Listen_Exception : Boolean := False;

         task Listen;
         task body Listen
         is
         begin
            delay 2.0;
            S_Server.Listen;

         exception
            when E : others =>
               Ada.Text_IO.Put_Line
                 (Ada.Exceptions.Exception_Information (X => E));
               Listen_Exception := True;
         end Listen;
      begin
         Connect_Retry_On_Refused (Socket => S_Client,
                                   Path   => Path,
                                   Count  => 6);

         Assert (Condition => not Listen_Exception,
                 Message   => "Exception in listener");

         if not Listen'Terminated then
            abort Listen;
         end if;

      exception
         when others =>
            if not Listen'Terminated then
               abort Listen;
            end if;
            Cleanup;
            raise;
      end;

      Cleanup;

   exception
      when others =>
         Cleanup;
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

      delay 0.3;
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
         raise;
   end Execute_Nonterminating_Command;

   -------------------------------------------------------------------------

   procedure Execute_Shell_Environment
   is
      package ENV renames Ada.Environment_Variables;

      Name        : constant String := "SPAWN_MANAGER_TEST_ENV";
      Original    : Unbounded_String;
      Was_Set     : constant Boolean := ENV.Exists (Name => Name);
      Initialized : Boolean := False;

      procedure Restore_Environment;
      --  Restore the caller environment after the manager snapshot test.

      procedure Restore_Environment
      is
      begin
         if Was_Set then
            ENV.Set (Name => Name, Value => To_String (Original));
         else
            ENV.Clear (Name => Name);
         end if;
      end Restore_Environment;
   begin
      if Was_Set then
         Original := To_Unbounded_String (ENV.Value (Name => Name));
      end if;
      ENV.Set (Name => Name, Value => "manager value");
      Spawn.Pool.Init (Log => Ada.Text_IO.Put_Line'Access);
      Initialized := True;

      --  Later caller mutation must not alter the already running manager.

      ENV.Set (Name => Name, Value => "caller value");
      Spawn.Pool.Execute
        (Command => "test ""$" & Name & """ = 'manager value'");

      Spawn.Pool.Cleanup;
      Initialized := False;
      Restore_Environment;

   exception
      when others =>
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         Restore_Environment;
         raise;
   end Execute_Shell_Environment;

   -------------------------------------------------------------------------

   procedure Execute_Shell_Syntax
   is
   begin
      Spawn.Pool.Init (Log => Ada.Text_IO.Put_Line'Access);
      Spawn.Pool.Execute
        (Command => "test ""$(printf '%s' 'a b')"" = 'a b'"
         & " && test $((2 + 3)) -eq 5");

      begin
         Spawn.Pool.Execute (Command => "false | true");
         Fail (Message => "pipefail did not reject the pipeline");
      exception
         when Spawn.Pool.Command_Failed => null;
      end;

      --  A normal command failure does not poison the legacy manager.

      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;

   exception
      when others =>
         Spawn.Pool.Cleanup;
         raise;
   end Execute_Shell_Syntax;

   -------------------------------------------------------------------------

   procedure Execute_Signal_Mask
   is
      Mask_Saved : Boolean := False;
   begin
      Assert
        (Condition => Block_Test_Signal = 0,
         Message   => "unable to prepare inherited signal mask");
      Mask_Saved := True;

      Spawn.Pool.Init (Log => Ada.Text_IO.Put_Line'Access);
      Spawn.Pool.Execute
        (Command => "grep -Eq '^SigBlk:[[:space:]]+0+$' "
         & "/proc/self/status");
      Spawn.Pool.Cleanup;

      Assert
        (Condition => Restore_Test_Signal_Mask = 0,
         Message   => "unable to restore inherited signal mask");
      Mask_Saved := False;

   exception
      when others =>
         Spawn.Pool.Cleanup;
         if Mask_Saved then
            Mask_Saved := Restore_Test_Signal_Mask /= 0;
         end if;
         raise;
   end Execute_Signal_Mask;

   -------------------------------------------------------------------------

   procedure Execute_Working_Directories
   is
      use Ada.Directories;

      Root : constant String := "obj/directory-"
        & Anet.Util.Random_String (Len => 8);
      First_Directory  : constant String := Root & "/first";
      Second_Directory : constant String := Root & "/second";
      Missing_Directory : constant String := Root & "/missing";
      Output_Path : constant String := Current_Directory & "/" & Root
        & "/pwd.out";

      procedure Assert_Directory (Expected : String);
      --  Execute pwd in Expected and verify the child-visible directory.

      procedure Assert_Directory (Expected : String)
      is
         Output : Ada.Text_IO.File_Type;
      begin
         Spawn.Pool.Execute
           (Command   => "pwd > " & Output_Path,
            Directory => Expected);
         Ada.Text_IO.Open
           (File => Output,
            Mode => Ada.Text_IO.In_File,
            Name => Output_Path,
            Form => "shared=no");
         Assert
           (Condition => Ada.Text_IO.Get_Line (File => Output) = Expected,
            Message   => "child working directory changed");
         Ada.Text_IO.Close (File => Output);

      exception
         when others =>
            if Ada.Text_IO.Is_Open (File => Output) then
               Ada.Text_IO.Close (File => Output);
            end if;
            raise;
      end Assert_Directory;
   begin
      Create_Path (New_Directory => First_Directory);
      Create_Path (New_Directory => Second_Directory);
      Spawn.Pool.Init (Log => Ada.Text_IO.Put_Line'Access);

      Assert_Directory (Expected => Full_Name (First_Directory));

      begin
         Spawn.Pool.Execute
           (Command   => "/bin/true",
            Directory => Missing_Directory);
         Fail (Message => "Missing working directory accepted");

      exception
         when Spawn.Pool.Command_Failed => null;
      end;

      Assert_Directory (Expected => Full_Name (Second_Directory));
      Spawn.Pool.Cleanup;
      Delete_Tree (Directory => Root);

   exception
      when others =>
         Spawn.Pool.Cleanup;
         if Exists (Name => Root) then
            Delete_Tree (Directory => Root);
         end if;
         raise;
   end Execute_Working_Directories;

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
        (Routine => Execute_Shell_Environment'Access,
         Name    => "Preserve shell manager environment");
      T.Add_Test_Routine
        (Routine => Execute_Shell_Syntax'Access,
         Name    => "Preserve shell syntax and pipefail");
      T.Add_Test_Routine
        (Routine => Execute_Signal_Mask'Access,
         Name    => "Preserve empty child signal mask");
      T.Add_Test_Routine
        (Routine => Execute_Working_Directories'Access,
         Name    => "Preserve per-request working directories");
      T.Add_Test_Routine
        (Routine => Parallel_Execution'Access,
         Name    => "Parallel execution");
      T.Add_Test_Routine
        (Routine => Pid_Setup_Target'Access,
         Name    => "Preserve manager PID callback");
      T.Add_Test_Routine
        (Routine => Pool_Depleted'Access,
         Name    => "Pool depleted");
      T.Add_Test_Routine
        (Routine => Relative_Socket_Transport'Access,
         Name    => "Preserve short relative socket transport");
      T.Add_Test_Routine
        (Routine => Command_Timeout'Access,
         Name    => "Command timeout");
      T.Add_Test_Routine
        (Routine => Timeout_Descendant_Group'Access,
         Name    => "Timeout descendant process group");
      T.Add_Test_Routine
        (Routine => Invalid_Socket_Directory'Access,
         Name    => "Invalid socket directory");
      T.Add_Test_Routine
        (Routine => Invalid_Socket_Path'Access,
         Name    => "Invalid socket path");
      T.Add_Test_Routine
        (Routine => Invalid_Socket_Path_Relative'Access,
         Name    => "Invalid relative socket path");
      T.Add_Test_Routine
        (Routine => Cleanup_Relative_Socket'Access,
         Name    => "Cleanup relative socket");
      T.Add_Test_Routine
        (Routine => Cleanup_Socket_After_Delete_Error'Access,
         Name    => "Continue cleanup after delete error");
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
      Fail (Message => "Exception expected");

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
      Fail (Message => "Exception expected");

   exception
      when Spawn.Pool.Pool_Error =>
         Ada.Directories.Delete_Directory (Directory => Dir);
   end Invalid_Socket_Path;

   -------------------------------------------------------------------------

   procedure Invalid_Socket_Path_Relative
   is
      use Ada.Directories;

      Dir : constant String := "obj/"
        & Anet.Util.Random_String (Len => 96);
   begin
      Create_Directory (New_Directory => Dir);

      Spawn.Pool.Init (Socket_Dir => Dir,
                       Log        => Ada.Text_IO.Put_Line'Access);
      Delete_Directory (Directory => Dir);
      Fail (Message => "Exception expected");

   exception
      when E : Spawn.Pool.Pool_Error =>
         Delete_Directory (Directory => Dir);
         Assert
           (Condition => Ada.Strings.Fixed.Index
              (Source  => Ada.Exceptions.Exception_Message (X => E),
               Pattern => "UNIX path too long '" & Dir
                 & "/spawn_manager-") = 1,
            Message   => "Relative socket diagnostic omits selected path");
      when others =>
         if Exists (Name => Dir) then
            Delete_Directory (Directory => Dir);
         end if;
         raise;
   end Invalid_Socket_Path_Relative;

   -------------------------------------------------------------------------

   procedure Log_A_File
   is
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
         for I in Task_Array'Range loop
            if not Task_Array (I)'Terminated then
               abort Task_Array (I);
            end if;
         end loop;
         raise;
   end Parallel_Execution;

   -------------------------------------------------------------------------

   procedure Pid_Setup_Target
   is
      use Ada.Directories;

      Manager_PID : Integer := -1;
      Output_Path : constant String := Current_Directory
        & "/obj/pid-setup-" & Anet.Util.Random_String (Len => 8)
        & ".out";

      procedure Capture_Manager
        (Descriptor : GNAT.Expect.Process_Descriptor);
      --  Record the process selected by the public compatibility callback.

      procedure Capture_Manager
        (Descriptor : GNAT.Expect.Process_Descriptor)
      is
      begin
         Manager_PID := Integer
           (GNAT.Expect.Get_Pid (Descriptor => Descriptor));
      end Capture_Manager;
   begin
      Spawn.Pool.Init (Log => Ada.Text_IO.Put_Line'Access);
      Spawn.Pool.Execute
        (Command   => "printf '%s\n' ""$PPID"" > " & Output_Path,
         Pid_Setup => Capture_Manager'Access);

      Assert (Condition => Manager_PID > 0,
              Message   => "pid-setup callback was not called");

      declare
         Output : Ada.Text_IO.File_Type;
      begin
         Ada.Text_IO.Open
           (File => Output,
            Mode => Ada.Text_IO.In_File,
            Name => Output_Path,
            Form => "shared=no");
         Assert
           (Condition => Integer'Value
              (Ada.Text_IO.Get_Line (File => Output)) = Manager_PID,
            Message   => "pid-setup callback did not receive manager PID");
         Ada.Text_IO.Close (File => Output);
      end;

      Spawn.Pool.Cleanup;
      Delete_File (Name => Output_Path);

   exception
      when others =>
         Spawn.Pool.Cleanup;
         if Exists (Name => Output_Path) then
            Delete_File (Name => Output_Path);
         end if;
         raise;
   end Pid_Setup_Target;

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
         for I in Task_Array'Range loop
            if not Task_Array (I)'Terminated then
               abort Task_Array (I);
            end if;
         end loop;
         raise;
   end Pool_Depleted;

   -------------------------------------------------------------------------

   procedure Raise_Delete_Error (Filename : String)
   is
      pragma Unreferenced (Filename);
   begin
      raise Anet.OS.IO_Error with "injected delete failure";
   end Raise_Delete_Error;

   -------------------------------------------------------------------------

   procedure Relative_Socket_Transport
   is
      use Ada.Directories;

      Directory : constant String := "obj/deep-"
        & Anet.Util.Random_String (Len => 68);
      Address_Suffix : constant String
        := "/.sp-123456789012/m-12345678";
      Relative_Address : constant String := Directory & Address_Suffix;
      Initialized : Boolean := False;
   begin
      Create_Directory (New_Directory => Directory);
      Assert
        (Condition => Anet.Sockets.Unix.Is_Valid
           (Path => Relative_Address),
         Message => "relative socket fixture exceeds the transport limit");
      Assert
        (Condition => not Anet.Sockets.Unix.Is_Valid
           (Path => Full_Name (Name => Directory) & Address_Suffix),
         Message => "absolute socket fixture does not exceed the limit");

      Spawn.Pool.Init (Socket_Dir => Directory,
                       Log        => Ada.Text_IO.Put_Line'Access);
      Initialized := True;
      Spawn.Pool.Execute (Command => "/bin/true");
      Spawn.Pool.Cleanup;
      Initialized := False;
      Delete_Directory (Directory => Directory);

   exception
      when others =>
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         if Exists (Name => Directory) then
            Delete_Tree (Directory => Directory);
         end if;
         raise;
   end Relative_Socket_Transport;

   -------------------------------------------------------------------------

   procedure Test_Log (Msg : String)
   is
   begin
      Test_Buffer := Test_Buffer & Msg & ASCII.LF;
   end Test_Log;

   -------------------------------------------------------------------------

   procedure Test_Log_Error (Msg : String)
   is
   begin
      raise Test_Log_Exception;
   end Test_Log_Error;

   -------------------------------------------------------------------------

   procedure Timeout_Descendant_Group
   is
      use Ada.Directories;

      Pid_File    : constant String := "obj/timeout-descendant.pid";
      Initialized : Boolean := False;
   begin
      if Exists (Name => Pid_File) then
         Delete_File (Name => Pid_File);
      end if;
      Spawn.Pool.Init (Log => Ada.Text_IO.Put_Line'Access);
      Initialized := True;

      begin
         Spawn.Pool.Execute
           (Command => "sleep 60 & echo $! > " & Pid_File & "; wait",
            Timeout => 500);
         Fail (Message => "Failure expected");
      exception
         when Spawn.Pool.Command_Failed => null;
      end;

      Spawn.Pool.Execute
        (Command => "test -s " & Pid_File
         & " && ! kill -0 $(cat " & Pid_File & ") 2>/dev/null");
      Spawn.Pool.Cleanup;
      Initialized := False;
      Delete_File (Name => Pid_File);

   exception
      when others =>
         if Initialized then
            Spawn.Pool.Cleanup;
         end if;
         if Exists (Name => Pid_File) then
            Delete_File (Name => Pid_File);
         end if;
         raise;
   end Timeout_Descendant_Group;

end Spawn.Pool.Tests;
