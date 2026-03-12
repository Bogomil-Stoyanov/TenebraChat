declare module 'tweetnacl-util' {
  /** Encode Uint8Array to Base64 string. */
  export function encodeBase64(data: Uint8Array): string;
  /** Decode Base64 string to Uint8Array. */
  export function decodeBase64(data: string): Uint8Array;
  /** Encode Uint8Array to UTF-8 string. */
  export function encodeUTF8(data: Uint8Array): string;
  /** Decode UTF-8 string to Uint8Array. */
  export function decodeUTF8(data: string): Uint8Array;
}
