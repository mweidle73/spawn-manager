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

package body Spawn.Protocol is

   use type Ada.Streams.Stream_Element_Array;
   use type Ada.Streams.Stream_Element_Offset;
   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;

   Magic : constant Ada.Streams.Stream_Element_Array (1 .. 4)
     := (Character'Pos ('S'),
         Character'Pos ('P'),
         Character'Pos ('W'),
         Character'Pos ('N'));

   Protocol_Version : constant Interfaces.Unsigned_16 := 1;

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
