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
with Interfaces;

package body Spawn.Protocol.Tests is

   use Ahven;
   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
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
   end Initialize;

end Spawn.Protocol.Tests;
