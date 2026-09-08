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

with Ada.Streams;
with Ada.Strings.Unbounded;
with Interfaces;

package body Spawn.Protocol.Tests is

   use Ahven;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_32;

   procedure Exec_Golden_Data
   is
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. 61)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#01#, 16#00#, 16#02#,
            16#00#, 16#00#, 16#00#, 16#31#,
            16#00#, 16#00#, 16#00#, 16#02#, 16#2f#, 16#78#,
            16#00#, 16#00#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#61#,
            16#00#, 16#00#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#45#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#56#,
            16#00#, 16#00#, 16#00#, 16#00#,
            16#00#,
            16#01#, 16#00#, 16#00#, 16#00#, 16#02#, 16#2f#, 16#65#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#);
      Expected : Exec_Request_Type;
      Data     : Ada.Streams.Stream_Element_Array (Golden'Range);
      Decoded  : Exec_Request_Type;
   begin
      Expected.Executable := Ada.Strings.Unbounded.To_Unbounded_String ("/x");
      Expected.Arguments.Append ("a");
      Expected.Environment.Append
        ((Name  => Ada.Strings.Unbounded.To_Unbounded_String ("E"),
          Value => Ada.Strings.Unbounded.To_Unbounded_String ("V")));
      Expected.Directory := Ada.Strings.Unbounded.Null_Unbounded_String;
      Expected.Standard_Output := (Mode => Null_Stream);
      Expected.Standard_Error :=
        (Mode => Truncate_File,
         Path => Ada.Strings.Unbounded.To_Unbounded_String ("/e"));
      Expected.Timeout := -1;

      Assert
        (Condition => Exec_Request_Frame_Length
           (Request      => Expected,
            Active_Bound => Maximum_Frame_Size) = Golden'Length,
         Message   => "exec-request frame length differs");
      Encode_Exec_Request
        (Request      => Expected,
         Active_Bound => Maximum_Frame_Size,
         Data         => Data);
      Assert (Condition => Data = Golden,
              Message   => "exec-request golden bytes differ");

      Decode_Exec_Request
        (Data         => Golden,
         Active_Bound => Maximum_Frame_Size,
         Request      => Decoded);
      Assert (Condition => Decoded = Expected,
              Message   => "decoded exec request differs");
   end Exec_Golden_Data;

   -------------------------------------------------------------------------

   procedure Exec_Rejects_Invalid_Data
   is
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. 61)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#01#, 16#00#, 16#02#,
            16#00#, 16#00#, 16#00#, 16#31#,
            16#00#, 16#00#, 16#00#, 16#02#, 16#2f#, 16#78#,
            16#00#, 16#00#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#61#,
            16#00#, 16#00#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#45#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#56#,
            16#00#, 16#00#, 16#00#, 16#00#,
            16#00#,
            16#01#, 16#00#, 16#00#, 16#00#, 16#02#, 16#2f#, 16#65#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#);
      Request : Exec_Request_Type;

      procedure Reject_Protocol
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String);
      --  Assert that Data is rejected as structurally invalid.

      procedure Reject_Request
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String);
      --  Assert that Data is rejected as semantically invalid.

      procedure Reject_Protocol
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String)
      is
      begin
         begin
            Decode_Exec_Request
              (Data         => Data,
               Active_Bound => Maximum_Frame_Size,
               Request      => Request);
            Fail (Message => Name & " accepted");
         exception
            when Protocol_Error => null;
         end;
      end Reject_Protocol;

      procedure Reject_Request
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String)
      is
      begin
         begin
            Decode_Exec_Request
              (Data         => Data,
               Active_Bound => Maximum_Frame_Size,
               Request      => Request);
            Fail (Message => Name & " accepted");
         exception
            when Request_Error => null;
         end;
      end Reject_Request;
   begin
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (8) := 1;
         Reject_Protocol (Data => Data, Name => "wrong exec message kind");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (46) := 2;
         Reject_Protocol (Data => Data, Name => "unknown stream mode");
      end;
      declare
         Data : constant Ada.Streams.Stream_Element_Array (1 .. 22)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#01#, 16#00#, 16#02#,
               16#00#, 16#00#, 16#00#, 16#0a#,
               16#00#, 16#00#, 16#00#, 16#02#, 16#2f#, 16#78#,
               16#00#, 16#00#, 16#04#, 16#01#);
      begin
         Reject_Request (Data => Data, Name => "oversized argument count");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (17) := Character'Pos ('x');
         Reject_Request (Data => Data, Name => "relative executable");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (36) := Character'Pos ('=');
         Reject_Request (Data => Data, Name => "invalid environment name");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (52) := Character'Pos ('e');
         Reject_Request (Data => Data, Name => "relative stream path");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden (1 .. 60);
      begin
         Data (12) := 16#30#;
         Reject_Protocol (Data => Data, Name => "truncated exec timeout");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array (1 .. 62) := (others => 0);
      begin
         Data (1 .. 61) := Golden;
         Data (12) := 16#32#;
         Reject_Protocol (Data => Data, Name => "trailing exec data");
      end;
   end Exec_Rejects_Invalid_Data;

   -------------------------------------------------------------------------

   procedure Exec_Roundtrip_And_Bounds
   is
      Request : Exec_Request_Type;
      Decoded : Exec_Request_Type;
   begin
      Request.Executable := Ada.Strings.Unbounded.To_Unbounded_String
        ("/usr/bin/printf");
      Request.Arguments.Append ("");
      Request.Arguments.Append
        ("spaces" & ASCII.HT & "quotes '"" glob *" & ASCII.LF);
      Request.Environment.Append
        ((Name  => Ada.Strings.Unbounded.To_Unbounded_String ("A"),
          Value => Ada.Strings.Unbounded.To_Unbounded_String
            ("one" & ASCII.LF & "two")));
      Request.Environment.Append
        ((Name  => Ada.Strings.Unbounded.To_Unbounded_String ("A"),
          Value => Ada.Strings.Unbounded.To_Unbounded_String ("replacement")));
      Request.Directory := Ada.Strings.Unbounded.To_Unbounded_String
        ("/tmp/work area");
      Request.Standard_Output :=
        (Mode => Truncate_File,
         Path => Ada.Strings.Unbounded.To_Unbounded_String ("/tmp/out file"));
      Request.Standard_Error := (Mode => Null_Stream);
      Request.Timeout := Timeout_Milliseconds'Last;
      declare
         Length : constant Positive := Exec_Request_Frame_Length
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size);
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
      begin
         Encode_Exec_Request
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size,
            Data         => Data);
         Decode_Exec_Request
           (Data         => Data,
            Active_Bound => Maximum_Frame_Size,
            Request      => Decoded);
         Assert (Condition => Decoded = Request,
                 Message   => "exec request did not round trip");
      end;

      Request.Arguments.Clear;
      Request.Environment.Clear;
      Request.Executable := Ada.Strings.Unbounded.To_Unbounded_String ("/x");
      Request.Directory := Ada.Strings.Unbounded.Null_Unbounded_String;
      Request.Standard_Output := (Mode => Null_Stream);
      Request.Standard_Error := (Mode => Null_Stream);
      Request.Timeout := 0;
      for Index in 1 .. Maximum_Vector_Length loop
         Request.Arguments.Append ("");
         Request.Environment.Append
           ((Name  => Ada.Strings.Unbounded.To_Unbounded_String ("E"),
             Value => Ada.Strings.Unbounded.Null_Unbounded_String));
      end loop;
      declare
         Length : constant Positive := Exec_Request_Frame_Length
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size);
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
      begin
         Encode_Exec_Request
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size,
            Data         => Data);
         Decode_Exec_Request
           (Data         => Data,
            Active_Bound => Maximum_Frame_Size,
            Request      => Decoded);
         Assert (Condition => Decoded = Request,
                 Message   => "maximum exec vectors did not round trip");
      end;

      Request.Arguments.Append ("");
      declare
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Exec_Request_Frame_Length
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "oversized encoded argument vector accepted");
      exception
         when Request_Error => null;
      end;

      Request.Arguments.Delete_Last;
      Request.Environment.Append
        ((Name  => Ada.Strings.Unbounded.To_Unbounded_String ("E"),
          Value => Ada.Strings.Unbounded.Null_Unbounded_String));
      declare
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Exec_Request_Frame_Length
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "oversized encoded environment accepted");
      exception
         when Request_Error => null;
      end;
   end Exec_Roundtrip_And_Bounds;

   -------------------------------------------------------------------------

   procedure Header_Bounds
   is
      Header : Header_Type;
      Data   : Ada.Streams.Stream_Element_Array (1 .. Header_Size);
   begin
      Encode_Header
        (Header => (Kind           => Shell_Request,
                    Payload_Length => Maximum_Frame_Size - Header_Size),
         Data   => Data);
      Decode_Header
        (Data         => Data,
         Active_Bound => Maximum_Frame_Size,
         Header       => Header);
      Assert
        (Condition => Header.Payload_Length
           = Maximum_Frame_Size - Header_Size,
         Message   => "maximum frame rejected");

      begin
         Decode_Header
           (Data         => Data,
            Active_Bound => Maximum_Frame_Size - 1,
            Header       => Header);
         Fail (Message => "oversized active frame accepted");
      exception
         when Protocol_Error => null;
      end;

      begin
         Validate_Active_Bound (Active_Bound => Maximum_Frame_Size + 1);
         Fail (Message => "oversized active bound accepted");
      exception
         when Protocol_Error => null;
      end;

      begin
         Encode_Header
           (Header =>
              (Kind           => Shell_Request,
               Payload_Length => Maximum_Frame_Size - Header_Size + 1),
            Data   => Data);
         Fail (Message => "oversized encoded frame accepted");
      exception
         when Protocol_Error => null;
      end;
   end Header_Bounds;

   -------------------------------------------------------------------------

   procedure Header_Golden_Data
   is
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. Header_Size)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#01#, 16#00#, 16#02#,
            16#00#, 16#00#, 16#00#, 16#24#);
      Data   : Ada.Streams.Stream_Element_Array (1 .. Header_Size);
      Header : Header_Type;
   begin
      Encode_Header
        (Header => (Kind => Exec_Request, Payload_Length => 16#24#),
         Data   => Data);
      Assert (Condition => Data = Golden,
              Message   => "header golden bytes differ");
      Decode_Header
        (Data         => Golden,
         Active_Bound => Maximum_Frame_Size,
         Header       => Header);
      Assert (Condition => Header.Kind = Exec_Request,
              Message   => "decoded message kind differs");
      Assert (Condition => Header.Payload_Length = 16#24#,
              Message   => "decoded payload length differs");
   end Header_Golden_Data;

   -------------------------------------------------------------------------

   procedure Header_Rejects_Invalid_Data
   is
      Valid : constant Ada.Streams.Stream_Element_Array (1 .. Header_Size)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#01#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#00#);
      Header : Header_Type;

      procedure Reject
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String);
      --  Assert that Data is rejected as an invalid header identified by Name.

      procedure Reject
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String)
      is
      begin
         begin
            Decode_Header
              (Data         => Data,
               Active_Bound => Maximum_Frame_Size,
               Header       => Header);
            Fail (Message => Name & " accepted");
         exception
            when Protocol_Error => null;
         end;
      end Reject;
   begin
      declare
         Data : Ada.Streams.Stream_Element_Array := Valid;
      begin
         Data (1) := 0;
         Reject (Data => Data, Name => "invalid magic");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Valid;
      begin
         Data (6) := 2;
         Reject (Data => Data, Name => "invalid version");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Valid;
      begin
         Data (8) := 4;
         Reject (Data => Data, Name => "invalid kind");
      end;
      Reject (Data => Valid (1 .. Header_Size - 1), Name => "short header");
   end Header_Rejects_Invalid_Data;

   -------------------------------------------------------------------------

   procedure Initialize (T : in out Testcase)
   is
   begin
      T.Set_Name (Name => "Spawn protocol tests");
      T.Add_Test_Routine
        (Routine => Exec_Golden_Data'Access,
         Name    => "Encode and decode golden exec request");
      T.Add_Test_Routine
        (Routine => Exec_Roundtrip_And_Bounds'Access,
         Name    => "Round trip bounded exec request");
      T.Add_Test_Routine
        (Routine => Exec_Rejects_Invalid_Data'Access,
         Name    => "Reject invalid exec requests");
      T.Add_Test_Routine
        (Routine => Header_Golden_Data'Access,
         Name    => "Encode and decode golden header");
      T.Add_Test_Routine
        (Routine => Header_Bounds'Access,
         Name    => "Enforce header frame bounds");
      T.Add_Test_Routine
        (Routine => Header_Rejects_Invalid_Data'Access,
         Name    => "Reject invalid headers");
      T.Add_Test_Routine
        (Routine => Result_Golden_Data'Access,
         Name    => "Encode and decode golden result");
      T.Add_Test_Routine
        (Routine => Result_Roundtrip_Alternatives'Access,
         Name    => "Round trip result alternatives");
      T.Add_Test_Routine
        (Routine => Result_Rejects_Invalid_Data'Access,
         Name    => "Reject invalid results");
      T.Add_Test_Routine
        (Routine => Shell_Golden_Data'Access,
         Name    => "Encode and decode golden shell request");
      T.Add_Test_Routine
        (Routine => Shell_Roundtrip_And_Bounds'Access,
         Name    => "Round trip bounded shell request");
      T.Add_Test_Routine
        (Routine => Shell_Rejects_Invalid_Data'Access,
         Name    => "Reject invalid shell requests");
   end Initialize;

   -------------------------------------------------------------------------

   procedure Result_Golden_Data
   is
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. 27)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#01#, 16#00#, 16#03#,
            16#00#, 16#00#, 16#00#, 16#0f#,
            16#03#, 16#00#, 16#0f#,
            16#00#, 16#00#, 16#00#, 16#02#,
            16#00#, 16#00#, 16#00#, 16#04#,
            16#65#, 16#78#, 16#65#, 16#63#);
      Expected : constant Result_Type
        := (Kind    => Spawn_Failed,
            Failure =>
              (Stage        => Exec_Target,
               Error_Number => 2,
               Diagnostic   => Ada.Strings.Unbounded.To_Unbounded_String
                 ("exec")));
      Data    : Ada.Streams.Stream_Element_Array (Golden'Range);
      Decoded : Result_Type;
   begin
      Assert
        (Condition => Result_Frame_Length
           (Result       => Expected,
            Active_Bound => Maximum_Frame_Size) = Golden'Length,
         Message   => "result frame length differs");
      Encode_Result
        (Result       => Expected,
         Active_Bound => Maximum_Frame_Size,
         Data         => Data);
      Assert (Condition => Data = Golden,
              Message   => "result golden bytes differ");

      Decode_Result
        (Data         => Golden,
         Active_Bound => Maximum_Frame_Size,
         Result       => Decoded);
      Assert (Condition => Decoded = Expected,
              Message   => "decoded result differs");
   end Result_Golden_Data;

   -------------------------------------------------------------------------

   procedure Result_Rejects_Invalid_Data
   is
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. 27)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#01#, 16#00#, 16#03#,
            16#00#, 16#00#, 16#00#, 16#0f#,
            16#03#, 16#00#, 16#0f#,
            16#00#, 16#00#, 16#00#, 16#02#,
            16#00#, 16#00#, 16#00#, 16#04#,
            16#65#, 16#78#, 16#65#, 16#63#);
      Result : Result_Type;

      procedure Reject
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String);
      --  Assert that Data is rejected as an invalid result.

      procedure Reject
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String)
      is
      begin
         begin
            Decode_Result
              (Data         => Data,
               Active_Bound => Maximum_Frame_Size,
               Result       => Result);
            Fail (Message => Name & " accepted");
         exception
            when Protocol_Error => null;
         end;
      end Reject;
   begin
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (8) := 1;
         Reject (Data => Data, Name => "wrong result message kind");
      end;
      declare
         Data : constant Ada.Streams.Stream_Element_Array (1 .. 13)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#01#, 16#00#, 16#03#,
               16#00#, 16#00#, 16#00#, 16#01#,
               16#06#);
      begin
         Reject (Data => Data, Name => "unknown result kind");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (15) := 16#12#;
         Reject (Data => Data, Name => "unknown failure stage");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden (1 .. 26);
      begin
         Data (12) := 16#0e#;
         Reject (Data => Data, Name => "truncated result diagnostic");
      end;
      declare
         Data : constant Ada.Streams.Stream_Element_Array (1 .. 14)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#01#, 16#00#, 16#03#,
               16#00#, 16#00#, 16#00#, 16#02#,
               16#02#, 16#00#);
      begin
         Reject (Data => Data, Name => "trailing result data");
      end;
      declare
         Data : constant Ada.Streams.Stream_Element_Array (1 .. 17)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#01#, 16#00#, 16#03#,
               16#00#, 16#00#, 16#00#, 16#05#,
               16#05#, 16#00#, 16#00#, 16#10#, 16#01#);
      begin
         Reject (Data => Data, Name => "oversized result diagnostic");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (24) := 0;
         Reject (Data => Data, Name => "NUL result diagnostic");
      end;
   end Result_Rejects_Invalid_Data;

   -------------------------------------------------------------------------

   procedure Result_Roundtrip_Alternatives
   is
      procedure Check (Expected : Result_Type; Name : String);
      --  Assert that Expected retains its discriminant and complete payload.

      procedure Check (Expected : Result_Type; Name : String)
      is
         Length : constant Positive := Result_Frame_Length
           (Result       => Expected,
            Active_Bound => Maximum_Frame_Size);
         Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Length));
         Decoded : Result_Type;
      begin
         Encode_Result
           (Result       => Expected,
            Active_Bound => Maximum_Frame_Size,
            Data         => Data);
         Decode_Result
           (Data         => Data,
            Active_Bound => Maximum_Frame_Size,
            Result       => Decoded);
         Assert (Condition => Decoded = Expected,
                 Message   => Name & " did not round trip");
      end Check;
   begin
      Check (Expected => (Kind => Exited, Exit_Status => 16#fedc_ba98#),
             Name     => "exit result");
      Check (Expected => (Kind => Signaled, Signal_Number => 15),
             Name     => "signal result");
      Check (Expected => (Kind => Timed_Out),
             Name     => "timeout result");
      Check
        (Expected =>
           (Kind    => Spawn_Failed,
            Failure =>
              (Stage        => Open_Stdout,
               Error_Number => 13,
               Diagnostic   => Ada.Strings.Unbounded.To_Unbounded_String
                 ("permission denied"))),
         Name => "spawn-failure result");
      Check
        (Expected =>
           (Kind       => Request_Rejected,
            Diagnostic => Ada.Strings.Unbounded.To_Unbounded_String
              ("bad request")),
         Name => "request-rejection result");
      Check
        (Expected =>
           (Kind       => Protocol_Failed,
            Diagnostic => Ada.Strings.Unbounded.To_Unbounded_String
              ("bad frame")),
         Name => "protocol-failure result");

      declare
         Maximum : constant String (1 .. Maximum_Diagnostic_Size)
           := (others => 'd');
      begin
         Check
           (Expected =>
              (Kind       => Protocol_Failed,
               Diagnostic => Ada.Strings.Unbounded.To_Unbounded_String
                 (Maximum)),
            Name => "maximum diagnostic");
      end;

      declare
         Too_Long : constant String (1 .. Maximum_Diagnostic_Size + 1)
           := (others => 'd');
         Invalid : constant Result_Type
           := (Kind       => Protocol_Failed,
               Diagnostic => Ada.Strings.Unbounded.To_Unbounded_String
                 (Too_Long));
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Result_Frame_Length
           (Result       => Invalid,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "oversized encoded result diagnostic accepted");
      exception
         when Protocol_Error => null;
      end;

      declare
         Invalid : constant Result_Type
           := (Kind       => Request_Rejected,
               Diagnostic => Ada.Strings.Unbounded.To_Unbounded_String
                 ("a" & ASCII.NUL & "b"));
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Result_Frame_Length
           (Result       => Invalid,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "encoded result diagnostic with NUL accepted");
      exception
         when Protocol_Error => null;
      end;
   end Result_Roundtrip_Alternatives;

   -------------------------------------------------------------------------

   procedure Shell_Golden_Data
   is
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. 38)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#01#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#1a#,
            16#00#, 16#00#, 16#00#, 16#09#,
            16#2f#, 16#62#, 16#69#, 16#6e#,
            16#2f#, 16#74#, 16#72#, 16#75#, 16#65#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#2f#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#);
      Request : constant Shell_Request_Type
        := (Command   => Ada.Strings.Unbounded.To_Unbounded_String
                          ("/bin/true"),
            Directory => Ada.Strings.Unbounded.To_Unbounded_String ("/"),
            Timeout   => -1);
      Data    : Ada.Streams.Stream_Element_Array (Golden'Range);
      Decoded : Shell_Request_Type;
   begin
      Assert
        (Condition => Shell_Request_Frame_Length
           (Request      => Request,
            Active_Bound => Maximum_Frame_Size) = Golden'Length,
         Message   => "shell-request frame length differs");
      Encode_Shell_Request
        (Request      => Request,
         Active_Bound => Maximum_Frame_Size,
         Data         => Data);
      Assert (Condition => Data = Golden,
              Message   => "shell-request golden bytes differ");

      Decode_Shell_Request
        (Data         => Golden,
         Active_Bound => Maximum_Frame_Size,
         Request      => Decoded);
      Assert
        (Condition => Ada.Strings.Unbounded.To_String (Decoded.Command)
           = "/bin/true",
         Message   => "decoded shell command differs");
      Assert
        (Condition => Ada.Strings.Unbounded.To_String (Decoded.Directory)
           = "/",
         Message   => "decoded shell directory differs");
      Assert (Condition => Decoded.Timeout = -1,
              Message   => "decoded shell timeout differs");
   end Shell_Golden_Data;

   -------------------------------------------------------------------------

   procedure Shell_Rejects_Invalid_Data
   is
      Golden : constant Ada.Streams.Stream_Element_Array (1 .. 38)
        := (16#53#, 16#50#, 16#57#, 16#4e#,
            16#00#, 16#01#, 16#00#, 16#01#,
            16#00#, 16#00#, 16#00#, 16#1a#,
            16#00#, 16#00#, 16#00#, 16#09#,
            16#2f#, 16#62#, 16#69#, 16#6e#,
            16#2f#, 16#74#, 16#72#, 16#75#, 16#65#,
            16#00#, 16#00#, 16#00#, 16#01#, 16#2f#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#,
            16#ff#, 16#ff#, 16#ff#, 16#ff#);
      Request : Shell_Request_Type;

      procedure Reject_Protocol
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String);
      --  Assert that Data is rejected as structurally invalid.

      procedure Reject_Request
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String);
      --  Assert that Data is rejected as semantically invalid.

      procedure Reject_Protocol
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String)
      is
      begin
         begin
            Decode_Shell_Request
              (Data         => Data,
               Active_Bound => Maximum_Frame_Size,
               Request      => Request);
            Fail (Message => Name & " accepted");
         exception
            when Protocol_Error => null;
         end;
      end Reject_Protocol;

      procedure Reject_Request
        (Data : Ada.Streams.Stream_Element_Array;
         Name : String)
      is
      begin
         begin
            Decode_Shell_Request
              (Data         => Data,
               Active_Bound => Maximum_Frame_Size,
               Request      => Request);
            Fail (Message => Name & " accepted");
         exception
            when Request_Error => null;
         end;
      end Reject_Request;
   begin
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (8) := 2;
         Reject_Protocol (Data => Data, Name => "wrong shell kind");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden (1 .. 37);
      begin
         Data (12) := 16#19#;
         Reject_Protocol (Data => Data, Name => "truncated shell timeout");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array (1 .. 39) := (others => 0);
      begin
         Data (1 .. 38) := Golden;
         Data (12) := 16#1b#;
         Reject_Protocol (Data => Data, Name => "trailing shell data");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (17) := 0;
         Reject_Request (Data => Data, Name => "NUL shell command");
      end;
      declare
         Data : Ada.Streams.Stream_Element_Array := Golden;
      begin
         Data (38) := 16#fe#;
         Reject_Request (Data => Data, Name => "negative shell timeout");
      end;
      declare
         Data : constant Ada.Streams.Stream_Element_Array (1 .. 16)
           := (16#53#, 16#50#, 16#57#, 16#4e#,
               16#00#, 16#01#, 16#00#, 16#01#,
               16#00#, 16#00#, 16#00#, 16#04#,
               16#00#, 16#01#, 16#00#, 16#01#);
      begin
         Reject_Request (Data => Data, Name => "oversized shell string");
      end;
   end Shell_Rejects_Invalid_Data;

   -------------------------------------------------------------------------

   procedure Shell_Roundtrip_And_Bounds
   is
      Command : constant String := "printf '%s" & ASCII.LF & "' 'a b'";
      Request : constant Shell_Request_Type
        := (Command   => Ada.Strings.Unbounded.To_Unbounded_String (Command),
            Directory => Ada.Strings.Unbounded.Null_Unbounded_String,
            Timeout   => 1_234);
      Length  : constant Positive := Shell_Request_Frame_Length
        (Request      => Request,
         Active_Bound => Maximum_Frame_Size);
      Data    : Ada.Streams.Stream_Element_Array
        (1 .. Ada.Streams.Stream_Element_Offset (Length));
      Decoded : Shell_Request_Type;
   begin
      Encode_Shell_Request
        (Request      => Request,
         Active_Bound => Maximum_Frame_Size,
         Data         => Data);
      Decode_Shell_Request
        (Data         => Data,
         Active_Bound => Maximum_Frame_Size,
         Request      => Decoded);
      Assert
        (Condition => Ada.Strings.Unbounded.To_String (Decoded.Command)
           = Command,
         Message   => "shell command did not round trip");
      Assert
        (Condition => Ada.Strings.Unbounded.To_String (Decoded.Directory)
           = "",
         Message   => "empty shell directory did not round trip");
      Assert (Condition => Decoded.Timeout = 1_234,
              Message   => "shell timeout did not round trip");

      declare
         Maximum : constant String (1 .. Maximum_String_Size)
           := (others => 'x');
         Boundary : constant Shell_Request_Type
           := (Command => Ada.Strings.Unbounded.To_Unbounded_String (Maximum),
               Directory => Ada.Strings.Unbounded.Null_Unbounded_String,
               Timeout => 0);
         Boundary_Length : constant Positive := Shell_Request_Frame_Length
           (Request      => Boundary,
            Active_Bound => Maximum_Frame_Size);
         Boundary_Data : Ada.Streams.Stream_Element_Array
           (1 .. Ada.Streams.Stream_Element_Offset (Boundary_Length));
      begin
         Encode_Shell_Request
           (Request      => Boundary,
            Active_Bound => Maximum_Frame_Size,
            Data         => Boundary_Data);
         Decode_Shell_Request
           (Data         => Boundary_Data,
            Active_Bound => Maximum_Frame_Size,
            Request      => Decoded);
         Assert
           (Condition => Ada.Strings.Unbounded.Length (Decoded.Command)
              = Maximum_String_Size,
            Message   => "maximum shell string did not round trip");
      end;

      declare
         Too_Long : constant String (1 .. Maximum_String_Size + 1)
           := (others => 'x');
         Invalid : constant Shell_Request_Type
           := (Command => Ada.Strings.Unbounded.To_Unbounded_String (Too_Long),
               Directory => Ada.Strings.Unbounded.Null_Unbounded_String,
               Timeout => 0);
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Shell_Request_Frame_Length
           (Request      => Invalid,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "oversized encoded shell string accepted");
      exception
         when Request_Error => null;
      end;

      declare
         Invalid : constant Shell_Request_Type
           := (Command => Ada.Strings.Unbounded.To_Unbounded_String
                          ("a" & ASCII.NUL & "b"),
               Directory => Ada.Strings.Unbounded.Null_Unbounded_String,
               Timeout => 0);
         Ignored : Positive := 1;
         pragma Unreferenced (Ignored);
      begin
         Ignored := Shell_Request_Frame_Length
           (Request      => Invalid,
            Active_Bound => Maximum_Frame_Size);
         Fail (Message => "encoded shell string with NUL accepted");
      exception
         when Request_Error => null;
      end;
   end Shell_Roundtrip_And_Bounds;

end Spawn.Protocol.Tests;
