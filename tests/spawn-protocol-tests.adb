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
        (Routine => Header_Golden_Data'Access,
         Name    => "Encode and decode golden header");
      T.Add_Test_Routine
        (Routine => Header_Bounds'Access,
         Name    => "Enforce header frame bounds");
      T.Add_Test_Routine
        (Routine => Header_Rejects_Invalid_Data'Access,
         Name    => "Reject invalid headers");
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
