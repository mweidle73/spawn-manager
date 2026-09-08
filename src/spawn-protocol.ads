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

package Spawn.Protocol is

   Header_Size            : constant := 12;
   Maximum_Frame_Size     : constant := 128 * 1024;
   Maximum_String_Size    : constant := 64 * 1024;
   Maximum_Vector_Length  : constant := 1024;
   Maximum_Diagnostic_Size : constant := 4 * 1024;

   type Message_Kind is (Shell_Request, Exec_Request, Result_Message);

   type Header_Type is record
      Kind           : Message_Kind;
      Payload_Length : Interfaces.Unsigned_32;
   end record;

   subtype Timeout_Milliseconds is Interfaces.Integer_64
     range Interfaces.Integer_64 (-1) .. Interfaces.Integer_64'Last;

   type Shell_Request_Type is record
      Command   : Ada.Strings.Unbounded.Unbounded_String;
      Directory : Ada.Strings.Unbounded.Unbounded_String;
      Timeout   : Timeout_Milliseconds;
   end record;

   procedure Decode_Header
     (Data         :     Ada.Streams.Stream_Element_Array;
      Active_Bound :     Positive;
      Header       : out Header_Type);
   --  Decode and validate one complete fixed header against Active_Bound.

   procedure Encode_Header
     (Header :     Header_Type;
      Data   : in out Ada.Streams.Stream_Element_Array);
   --  Encode Header into the first Header_Size bytes of Data.

   procedure Decode_Shell_Request
     (Data         :     Ada.Streams.Stream_Element_Array;
      Active_Bound :     Positive;
      Request      : out Shell_Request_Type);
   --  Decode one exact shell-request frame without accepting trailing bytes.

   procedure Encode_Shell_Request
     (Request      :     Shell_Request_Type;
      Active_Bound :     Positive;
      Data         : in out Ada.Streams.Stream_Element_Array);
   --  Encode one shell request into an exactly sized bounded Data array.

   function Frame_Length
     (Payload_Length : Interfaces.Unsigned_32;
      Active_Bound   : Positive)
      return Positive;
   --  Return the complete bounded frame length or raise Protocol_Error.

   function Shell_Request_Frame_Length
     (Request      : Shell_Request_Type;
      Active_Bound : Positive)
      return Positive;
   --  Return the exact encoded shell-request frame length.

   procedure Validate_Active_Bound (Active_Bound : Positive);
   --  Reject an active frame bound outside Header_Size .. Maximum_Frame_Size.

   Protocol_Error : exception;
   Request_Error  : exception;

end Spawn.Protocol;
