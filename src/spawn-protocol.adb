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

with Ada.Unchecked_Conversion;

package body Spawn.Protocol is

   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use type Interfaces.Integer_64;
   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   Magic : constant Ada.Streams.Stream_Element_Array (1 .. 4)
     := (Character'Pos ('S'),
         Character'Pos ('P'),
         Character'Pos ('W'),
         Character'Pos ('N'));

   Protocol_Version : constant Interfaces.Unsigned_16 := 1;

   function To_Integer_64 is new Ada.Unchecked_Conversion
     (Source => Interfaces.Unsigned_64,
      Target => Interfaces.Integer_64);

   function To_Unsigned_64 is new Ada.Unchecked_Conversion
     (Source => Interfaces.Integer_64,
      Target => Interfaces.Unsigned_64);

   function Decode_I64
     (Data  : Ada.Streams.Stream_Element_Array;
      First : Ada.Streams.Stream_Element_Offset)
      return Interfaces.Integer_64;
   --  Decode one two's-complement big-endian signed 64-bit field at First.

   procedure Decode_String
     (Data   :     Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset;
      Value  : out Ada.Strings.Unbounded.Unbounded_String);
   --  Decode one bounded non-NUL string and advance Cursor.

   function Decode_U16
     (Data  : Ada.Streams.Stream_Element_Array;
      First : Ada.Streams.Stream_Element_Offset)
      return Interfaces.Unsigned_16;
   --  Decode one big-endian unsigned 16-bit field at First.

   function Decode_U32
     (Data  : Ada.Streams.Stream_Element_Array;
      First : Ada.Streams.Stream_Element_Offset)
      return Interfaces.Unsigned_32;
   --  Decode one big-endian unsigned 32-bit field at First.

   procedure Encode_U16
     (Value :     Interfaces.Unsigned_16;
      Data  : in out Ada.Streams.Stream_Element_Array;
      First :     Ada.Streams.Stream_Element_Offset);
   --  Encode one big-endian unsigned 16-bit field at First.

   procedure Encode_I64
     (Value :     Interfaces.Integer_64;
      Data  : in out Ada.Streams.Stream_Element_Array;
      First :     Ada.Streams.Stream_Element_Offset);
   --  Encode one two's-complement big-endian signed 64-bit field at First.

   procedure Encode_String
     (Value  :     Ada.Strings.Unbounded.Unbounded_String;
      Data   : in out Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset);
   --  Encode one validated string and advance Cursor.

   procedure Encode_U32
     (Value :     Interfaces.Unsigned_32;
      Data  : in out Ada.Streams.Stream_Element_Array;
      First :     Ada.Streams.Stream_Element_Offset);
   --  Encode one big-endian unsigned 32-bit field at First.

   function Kind_From_Wire
     (Value : Interfaces.Unsigned_16)
      return Message_Kind;
   --  Decode one assigned message-kind value.

   function Kind_To_Wire
     (Kind : Message_Kind)
      return Interfaces.Unsigned_16;
   --  Return the assigned version 1 value for Kind.

   function String_Field_Length
     (Value : Ada.Strings.Unbounded.Unbounded_String)
      return Positive;
   --  Return the encoded string length after validating its semantic bound.

   procedure Decode_Header
     (Data         :     Ada.Streams.Stream_Element_Array;
      Active_Bound :     Positive;
      Header       : out Header_Type)
   is
      First : constant Ada.Streams.Stream_Element_Offset := Data'First;
   begin
      Validate_Active_Bound (Active_Bound => Active_Bound);
      if Data'Length /= Header_Size then
         raise Protocol_Error with "invalid header length";
      end if;
      if Data (First .. First + 3) /= Magic then
         raise Protocol_Error with "invalid protocol magic";
      end if;
      if Decode_U16 (Data => Data, First => First + 4) /= Protocol_Version
      then
         raise Protocol_Error with "unsupported protocol version";
      end if;
      Header.Kind := Kind_From_Wire
        (Value => Decode_U16 (Data => Data, First => First + 6));
      Header.Payload_Length := Decode_U32
        (Data => Data, First => First + 8);
      declare
         Ignored : constant Positive := Frame_Length
           (Payload_Length => Header.Payload_Length,
            Active_Bound   => Active_Bound);
         pragma Unreferenced (Ignored);
      begin
         null;
      end;
   end Decode_Header;

   -------------------------------------------------------------------------

   function Decode_I64
     (Data  : Ada.Streams.Stream_Element_Array;
      First : Ada.Streams.Stream_Element_Offset)
      return Interfaces.Integer_64
   is
      Value : Interfaces.Unsigned_64 := 0;
   begin
      for Offset in 0 .. 7 loop
         Value := Interfaces.Shift_Left (Value => Value, Amount => 8)
           or Interfaces.Unsigned_64
             (Data (First + Ada.Streams.Stream_Element_Offset (Offset)));
      end loop;
      return To_Integer_64 (Value);
   end Decode_I64;

   -------------------------------------------------------------------------

   procedure Decode_Shell_Request
     (Data         :     Ada.Streams.Stream_Element_Array;
      Active_Bound :     Positive;
      Request      : out Shell_Request_Type)
   is
      Header : Header_Type;
      Cursor : Ada.Streams.Stream_Element_Offset
        := Data'First + Header_Size;
      Raw_Timeout : Interfaces.Integer_64;
   begin
      if Data'Length < Header_Size then
         raise Protocol_Error with "shell frame shorter than header";
      end if;
      Decode_Header
        (Data         => Data (Data'First .. Data'First + Header_Size - 1),
         Active_Bound => Active_Bound,
         Header       => Header);
      if Header.Kind /= Shell_Request then
         raise Protocol_Error with "shell request has wrong message kind";
      end if;
      if Frame_Length
        (Payload_Length => Header.Payload_Length,
         Active_Bound   => Active_Bound) /= Data'Length
      then
         raise Protocol_Error with "shell frame length mismatch";
      end if;

      Decode_String (Data => Data, Cursor => Cursor, Value => Request.Command);
      Decode_String
        (Data   => Data,
         Cursor => Cursor,
         Value  => Request.Directory);
      if Data'Last - Cursor + 1 < 8 then
         raise Protocol_Error with "truncated shell timeout";
      end if;
      Raw_Timeout := Decode_I64 (Data => Data, First => Cursor);
      Cursor := Cursor + 8;
      if Raw_Timeout < -1 then
         raise Request_Error with "invalid shell timeout";
      end if;
      Request.Timeout := Timeout_Milliseconds (Raw_Timeout);
      if Cursor /= Data'Last + 1 then
         raise Protocol_Error with "trailing shell payload bytes";
      end if;
   end Decode_Shell_Request;

   -------------------------------------------------------------------------

   procedure Decode_String
     (Data   :     Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset;
      Value  : out Ada.Strings.Unbounded.Unbounded_String)
   is
      Length : Natural;
   begin
      if Data'Last - Cursor + 1 < 4 then
         raise Protocol_Error with "truncated string length";
      end if;
      declare
         Raw_Length : constant Interfaces.Unsigned_32
           := Decode_U32 (Data => Data, First => Cursor);
      begin
         if Raw_Length > Maximum_String_Size then
            raise Request_Error with "string exceeds protocol bound";
         end if;
         Length := Natural (Raw_Length);
      end;
      Cursor := Cursor + 4;
      if Data'Last - Cursor + 1 < Ada.Streams.Stream_Element_Offset (Length)
      then
         raise Protocol_Error with "truncated string data";
      end if;
      declare
         Result : String (1 .. Length);
      begin
         for Index in Result'Range loop
            Result (Index) := Character'Val (Data (Cursor));
            if Result (Index) = ASCII.NUL then
               raise Request_Error with "string contains NUL";
            end if;
            Cursor := Cursor + 1;
         end loop;
         Value := Ada.Strings.Unbounded.To_Unbounded_String (Result);
      end;
   end Decode_String;

   -------------------------------------------------------------------------

   function Decode_U16
     (Data  : Ada.Streams.Stream_Element_Array;
      First : Ada.Streams.Stream_Element_Offset)
      return Interfaces.Unsigned_16
   is
   begin
      return Interfaces.Shift_Left
        (Value  => Interfaces.Unsigned_16 (Data (First)),
         Amount => 8)
        or Interfaces.Unsigned_16 (Data (First + 1));
   end Decode_U16;

   -------------------------------------------------------------------------

   function Decode_U32
     (Data  : Ada.Streams.Stream_Element_Array;
      First : Ada.Streams.Stream_Element_Offset)
      return Interfaces.Unsigned_32
   is
      Result : Interfaces.Unsigned_32 := 0;
   begin
      for Offset in 0 .. 3 loop
         Result := Interfaces.Shift_Left (Value => Result, Amount => 8)
           or Interfaces.Unsigned_32
             (Data (First + Ada.Streams.Stream_Element_Offset (Offset)));
      end loop;
      return Result;
   end Decode_U32;

   -------------------------------------------------------------------------

   procedure Encode_Header
     (Header :     Header_Type;
      Data   : in out Ada.Streams.Stream_Element_Array)
   is
      First : constant Ada.Streams.Stream_Element_Offset := Data'First;
   begin
      declare
         Ignored : constant Positive := Frame_Length
           (Payload_Length => Header.Payload_Length,
            Active_Bound   => Maximum_Frame_Size);
         pragma Unreferenced (Ignored);
      begin
         null;
      end;
      if Data'Length < Header_Size then
         raise Protocol_Error with "header buffer too small";
      end if;
      Data (First .. First + 3) := Magic;
      Encode_U16
        (Value => Protocol_Version,
         Data  => Data,
         First => First + 4);
      Encode_U16
        (Value => Kind_To_Wire (Kind => Header.Kind),
         Data  => Data,
         First => First + 6);
      Encode_U32
        (Value => Header.Payload_Length,
         Data  => Data,
         First => First + 8);
   end Encode_Header;

   -------------------------------------------------------------------------

   procedure Encode_I64
     (Value :     Interfaces.Integer_64;
      Data  : in out Ada.Streams.Stream_Element_Array;
      First :     Ada.Streams.Stream_Element_Offset)
   is
      Raw : constant Interfaces.Unsigned_64 := To_Unsigned_64 (Value);
   begin
      for Offset in 0 .. 7 loop
         Data (First + Ada.Streams.Stream_Element_Offset (Offset))
           := Ada.Streams.Stream_Element
             (Interfaces.Shift_Right
                (Value  => Raw,
                 Amount => (7 - Offset) * 8)
              and 16#ff#);
      end loop;
   end Encode_I64;

   -------------------------------------------------------------------------

   procedure Encode_Shell_Request
     (Request      :     Shell_Request_Type;
      Active_Bound :     Positive;
      Data         : in out Ada.Streams.Stream_Element_Array)
   is
      Length : constant Positive := Shell_Request_Frame_Length
        (Request      => Request,
         Active_Bound => Active_Bound);
      Cursor : Ada.Streams.Stream_Element_Offset
        := Data'First + Header_Size;
   begin
      if Data'Length /= Length then
         raise Protocol_Error with "shell frame buffer length mismatch";
      end if;
      Encode_Header
        (Header =>
           (Kind           => Shell_Request,
            Payload_Length => Interfaces.Unsigned_32 (Length - Header_Size)),
         Data   => Data);
      Encode_String
        (Value  => Request.Command,
         Data   => Data,
         Cursor => Cursor);
      Encode_String
        (Value  => Request.Directory,
         Data   => Data,
         Cursor => Cursor);
      Encode_I64 (Value => Request.Timeout, Data => Data, First => Cursor);
      Cursor := Cursor + 8;
      if Cursor /= Data'Last + 1 then
         raise Program_Error with "shell frame length calculation differs";
      end if;
   end Encode_Shell_Request;

   -------------------------------------------------------------------------

   procedure Encode_String
     (Value  :     Ada.Strings.Unbounded.Unbounded_String;
      Data   : in out Ada.Streams.Stream_Element_Array;
      Cursor : in out Ada.Streams.Stream_Element_Offset)
   is
      Source : constant String := Ada.Strings.Unbounded.To_String (Value);
      Ignored : constant Positive := String_Field_Length (Value => Value);
      pragma Unreferenced (Ignored);
   begin
      Encode_U32
        (Value => Interfaces.Unsigned_32 (Source'Length),
         Data  => Data,
         First => Cursor);
      Cursor := Cursor + 4;
      for Item of Source loop
         Data (Cursor) := Ada.Streams.Stream_Element
           (Character'Pos (Item));
         Cursor := Cursor + 1;
      end loop;
   end Encode_String;

   -------------------------------------------------------------------------

   procedure Encode_U16
     (Value :     Interfaces.Unsigned_16;
      Data  : in out Ada.Streams.Stream_Element_Array;
      First :     Ada.Streams.Stream_Element_Offset)
   is
   begin
      Data (First) := Ada.Streams.Stream_Element
        (Interfaces.Shift_Right (Value => Value, Amount => 8) and 16#ff#);
      Data (First + 1) := Ada.Streams.Stream_Element (Value and 16#ff#);
   end Encode_U16;

   -------------------------------------------------------------------------

   procedure Encode_U32
     (Value :     Interfaces.Unsigned_32;
      Data  : in out Ada.Streams.Stream_Element_Array;
      First :     Ada.Streams.Stream_Element_Offset)
   is
   begin
      for Offset in 0 .. 3 loop
         Data (First + Ada.Streams.Stream_Element_Offset (Offset))
           := Ada.Streams.Stream_Element
             (Interfaces.Shift_Right
                (Value  => Value,
                 Amount => (3 - Offset) * 8)
              and 16#ff#);
      end loop;
   end Encode_U32;

   -------------------------------------------------------------------------

   function Frame_Length
     (Payload_Length : Interfaces.Unsigned_32;
      Active_Bound   : Positive)
      return Positive
   is
      Maximum_Payload : Interfaces.Unsigned_32;
   begin
      Validate_Active_Bound (Active_Bound => Active_Bound);
      Maximum_Payload := Interfaces.Unsigned_32
        (Active_Bound - Header_Size);
      if Payload_Length > Maximum_Payload then
         raise Protocol_Error with "frame exceeds active bound";
      end if;
      return Header_Size + Natural (Payload_Length);
   end Frame_Length;

   -------------------------------------------------------------------------

   function Kind_From_Wire
     (Value : Interfaces.Unsigned_16)
      return Message_Kind
   is
   begin
      case Value is
         when 1 => return Shell_Request;
         when 2 => return Exec_Request;
         when 3 => return Result_Message;
         when others =>
            raise Protocol_Error with "unknown message kind";
      end case;
   end Kind_From_Wire;

   -------------------------------------------------------------------------

   function Kind_To_Wire
     (Kind : Message_Kind)
      return Interfaces.Unsigned_16
   is
   begin
      case Kind is
         when Shell_Request  => return 1;
         when Exec_Request   => return 2;
         when Result_Message => return 3;
      end case;
   end Kind_To_Wire;

   -------------------------------------------------------------------------

   function Shell_Request_Frame_Length
     (Request      : Shell_Request_Type;
      Active_Bound : Positive)
      return Positive
   is
      Payload_Length : Natural := 8;
   begin
      Payload_Length := Payload_Length
        + String_Field_Length (Value => Request.Command);
      Payload_Length := Payload_Length
        + String_Field_Length (Value => Request.Directory);
      return Frame_Length
        (Payload_Length => Interfaces.Unsigned_32 (Payload_Length),
         Active_Bound   => Active_Bound);
   end Shell_Request_Frame_Length;

   -------------------------------------------------------------------------

   function String_Field_Length
     (Value : Ada.Strings.Unbounded.Unbounded_String)
      return Positive
   is
      Source : constant String := Ada.Strings.Unbounded.To_String (Value);
   begin
      if Source'Length > Maximum_String_Size then
         raise Request_Error with "string exceeds protocol bound";
      end if;
      for Item of Source loop
         if Item = ASCII.NUL then
            raise Request_Error with "string contains NUL";
         end if;
      end loop;
      return 4 + Source'Length;
   end String_Field_Length;

   -------------------------------------------------------------------------

   procedure Validate_Active_Bound (Active_Bound : Positive)
   is
   begin
      if Active_Bound < Header_Size
        or else Active_Bound > Maximum_Frame_Size
      then
         raise Protocol_Error with "invalid active frame bound";
      end if;
   end Validate_Active_Bound;

end Spawn.Protocol;
