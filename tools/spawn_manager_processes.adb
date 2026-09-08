--
--  Process Spawn Manager
--
--  Copyright (C) 2026 secunet Security Networks AG
--
--  This program is free software; you can redistribute it and/or
--  modify it under the terms of the GNU General Public License
--  as published by the Free Software Foundation; either version 2
--  of the License, or (at your option) any later version.
--
--  This program is distributed in the hope that it will be useful,
--  but WITHOUT ANY WARRANTY; without even the implied warranty of
--  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
--  General Public License for more details.
--
--  As a special exception, if other files instantiate generics from this
--  unit, or you link this unit with other files to produce an executable,
--  this unit does not by itself cause the resulting executable to be covered
--  by the GNU General Public License. This exception does not invalidate any
--  other reason why the executable might be covered by the GNU Public
--  License.
--

with Ada.Strings.Fixed;
with Interfaces.C;
with Interfaces.C.Strings;
with GNAT.OS_Lib;
with System;

package body Spawn_Manager_Processes is

   package C renames Interfaces.C;
   package CS renames Interfaces.C.Strings;
   package US renames Ada.Strings.Unbounded;

   use type C.int;
   use type CS.chars_ptr;

   Shell : constant String := "/bin/bash";

   type C_Result is record
      Kind          : C.int;
      Exit_Status   : C.int;
      Signal_Number : C.int;
      Stage         : C.int;
      Error_Number  : C.int;
   end record
     with Convention => C;

   type C_String_Array is array (Natural range <>) of aliased CS.chars_ptr
     with Convention => C;

   function C_Execute
     (Executable          : CS.chars_ptr;
      Arguments           : System.Address;
      Inherit_Environment : C.int;
      Environment         : System.Address;
      Directory           : CS.chars_ptr;
      Stdout_Mode         : C.int;
      Stdout_Path         : CS.chars_ptr;
      Stderr_Mode         : C.int;
      Stderr_Path         : CS.chars_ptr;
      Timeout_MS          : C.int;
      Result              : access C_Result)
      return C.int
     with Import,
          Convention    => C,
          External_Name => "spawn_posix_execute";
   --  Invoke the minimal manager-side POSIX execution boundary.

   function Has_Nul (Value : String) return Boolean;
   --  Return True if Value cannot be represented by execve.

   procedure Require_Absolute (Value : String; Name : String);
   --  Reject a non-absolute or non-C-compatible pathname.

   procedure Require_C_String (Value : String; Name : String);
   --  Reject a value which cannot be represented by a C string.

   function Create_Shell_Request
     (Command   : String;
      Directory : String;
      Timeout   : Integer)
      return Execution_Request
   is
      Arguments : String_Vectors.Vector;
   begin
      Arguments.Append ("-o");
      Arguments.Append ("pipefail");
      Arguments.Append ("-c");
      Arguments.Append (Command);
      return
        (Executable      => US.To_Unbounded_String (Shell),
         Arguments       => Arguments,
         Environment     => Environment_Vectors.Empty_Vector,
         Environment_Use => Inherit,
         Directory       => US.To_Unbounded_String (Directory),
         Standard_Output => (Mode => Null_Stream, Path => <>),
         Standard_Error  => (Mode => Null_Stream, Path => <>),
         Timeout_MS      => Timeout);
   end Create_Shell_Request;

   -------------------------------------------------------------------------

   function Diagnostic (Result : Execution_Result) return String
   is
      Error_Text : constant String
        := (if Result.Error_Number = 0 then ""
            else ": " & GNAT.OS_Lib.Errno_Message
              (Err => Integer (Result.Error_Number)));
   begin
      case Result.Kind is
         when Exited =>
            return "exited" & Result.Exit_Status'Image;
         when Signaled =>
            return "signaled" & Result.Signal_Number'Image;
         when Timed_Out =>
            return "timed out";
         when Spawn_Failed =>
            return "spawn failed at " & Result.Stage'Image & Error_Text;
         when Internal_Error =>
            return "internal error at " & Result.Stage'Image & Error_Text;
      end case;
   end Diagnostic;

   -------------------------------------------------------------------------

   function Execute (Request : Execution_Request) return Execution_Result
   is
      Argument_Count : constant Natural
        := Natural (Request.Arguments.Length);
      Environment_Count : constant Natural
        := Natural (Request.Environment.Length);
      C_Arguments : C_String_Array (0 .. Argument_Count + 1)
        := (others => CS.Null_Ptr);
      C_Environment : C_String_Array (0 .. Environment_Count)
        := (others => CS.Null_Ptr);

      Executable  : CS.chars_ptr := CS.Null_Ptr;
      Directory   : CS.chars_ptr := CS.Null_Ptr;
      Stdout_Path : CS.chars_ptr := CS.Null_Ptr;
      Stderr_Path : CS.chars_ptr := CS.Null_Ptr;
      Raw_Result  : aliased C_Result := (others => 0);
      Return_Code : C.int;

      procedure Free_Inputs;
      --  Release every C string allocated while translating Request.

      procedure Free_Inputs
      is
      begin
         for Item of C_Arguments loop
            if Item /= CS.Null_Ptr then
               CS.Free (Item);
            end if;
         end loop;
         for Item of C_Environment loop
            if Item /= CS.Null_Ptr then
               CS.Free (Item);
            end if;
         end loop;
         if Executable /= CS.Null_Ptr then
            CS.Free (Executable);
         end if;
         if Directory /= CS.Null_Ptr then
            CS.Free (Directory);
         end if;
         if Stdout_Path /= CS.Null_Ptr then
            CS.Free (Stdout_Path);
         end if;
         if Stderr_Path /= CS.Null_Ptr then
            CS.Free (Stderr_Path);
         end if;
      end Free_Inputs;

      function To_Result return Execution_Result;
      --  Validate C discriminants and translate the result to Ada.

      function To_Result return Execution_Result
      is
         Kind_Position  : constant Integer := Integer (Raw_Result.Kind);
         Stage_Position : constant Integer := Integer (Raw_Result.Stage);
      begin
         if Kind_Position not in Termination_Kind'Pos (Termination_Kind'First)
           .. Termination_Kind'Pos (Termination_Kind'Last)
           or else Stage_Position not in
             Failure_Stage'Pos (Failure_Stage'First)
             .. Failure_Stage'Pos (Failure_Stage'Last)
           or else Raw_Result.Signal_Number < 0
           or else Raw_Result.Error_Number < 0
         then
            return (Kind => Internal_Error, others => <>);
         end if;
         return
           (Kind          => Termination_Kind'Val (Kind_Position),
            Exit_Status   => Integer (Raw_Result.Exit_Status),
            Signal_Number => Natural (Raw_Result.Signal_Number),
            Stage         => Failure_Stage'Val (Stage_Position),
            Error_Number  => Natural (Raw_Result.Error_Number));
      end To_Result;

      Executable_Value : constant String := US.To_String (Request.Executable);
      Directory_Value  : constant String := US.To_String (Request.Directory);
   begin
      Require_Absolute (Value => Executable_Value, Name => "executable");
      Require_C_String (Value => Directory_Value, Name => "directory");
      if Request.Timeout_MS < -1 then
         raise Constraint_Error with "timeout must be -1 or nonnegative";
      end if;
      if Request.Environment_Use = Inherit
        and then not Request.Environment.Is_Empty
      then
         raise Constraint_Error with
           "inherited environment must not contain entries";
      end if;

      Executable := CS.New_String (Executable_Value);
      Directory := CS.New_String (Directory_Value);
      C_Arguments (0) := CS.New_String (Executable_Value);
      for Index in 1 .. Argument_Count loop
         declare
            Value : constant String
              := Request.Arguments.Element (Positive (Index));
         begin
            Require_C_String (Value => Value, Name => "argument");
            C_Arguments (Index) := CS.New_String (Value);
         end;
      end loop;

      for Index in 1 .. Environment_Count loop
         declare
            Item  : constant Environment_Entry
              := Request.Environment.Element (Positive (Index));
            Name  : constant String := US.To_String (Item.Name);
            Value : constant String := US.To_String (Item.Value);
         begin
            Require_C_String (Value => Name, Name => "environment name");
            Require_C_String (Value => Value, Name => "environment value");
            if Name'Length = 0
              or else Ada.Strings.Fixed.Index (Source => Name, Pattern => "=")
                /= 0
            then
               raise Constraint_Error with "invalid environment name";
            end if;
            C_Environment (Index - 1) := CS.New_String (Name & "=" & Value);
         end;
      end loop;

      if Request.Standard_Output.Mode = Truncate_File then
         declare
            Value : constant String
              := US.To_String (Request.Standard_Output.Path);
         begin
            Require_Absolute (Value => Value, Name => "stdout path");
            Stdout_Path := CS.New_String (Value);
         end;
      end if;
      if Request.Standard_Error.Mode = Truncate_File then
         declare
            Value : constant String
              := US.To_String (Request.Standard_Error.Path);
         begin
            Require_Absolute (Value => Value, Name => "stderr path");
            Stderr_Path := CS.New_String (Value);
         end;
      end if;

      Return_Code := C_Execute
        (Executable          => Executable,
         Arguments           => C_Arguments'Address,
         Inherit_Environment =>
           C.int (Boolean'Pos (Request.Environment_Use = Inherit)),
         Environment         => C_Environment'Address,
         Directory           => Directory,
         Stdout_Mode         =>
           C.int (Stream_Mode'Pos (Request.Standard_Output.Mode)),
         Stdout_Path         => Stdout_Path,
         Stderr_Mode         =>
           C.int (Stream_Mode'Pos (Request.Standard_Error.Mode)),
         Stderr_Path         => Stderr_Path,
         Timeout_MS          => C.int (Request.Timeout_MS),
         Result              => Raw_Result'Access);
      pragma Unreferenced (Return_Code);

      Free_Inputs;
      return To_Result;

   exception
      when others =>
         Free_Inputs;
         raise;
   end Execute;

   -------------------------------------------------------------------------

   function File_Stream (Path : String) return Stream_Specification
   is
   begin
      Require_Absolute (Value => Path, Name => "stream path");
      return (Mode => Truncate_File,
              Path => US.To_Unbounded_String (Path));
   end File_Stream;

   -------------------------------------------------------------------------

   function Has_Nul (Value : String) return Boolean
   is (Ada.Strings.Fixed.Index (Source => Value, Pattern => (1 => ASCII.NUL))
       /= 0);

   -------------------------------------------------------------------------

   procedure Require_Absolute (Value : String; Name : String)
   is
   begin
      Require_C_String (Value => Value, Name => Name);
      if Value'Length = 0 or else Value (Value'First) /= '/' then
         raise Constraint_Error with Name & " must be absolute";
      end if;
   end Require_Absolute;

   -------------------------------------------------------------------------

   procedure Require_C_String (Value : String; Name : String)
   is
   begin
      if Has_Nul (Value) then
         raise Constraint_Error with Name & " contains NUL";
      end if;
   end Require_C_String;

end Spawn_Manager_Processes;
