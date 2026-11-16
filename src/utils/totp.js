/**
 * TOTP (Time-based One-Time Password) - RFC 6238 / RFC 4226 구현체
 *
 * [보안 원칙]
 * 1. Math.random() 절대 금지: 암호학적 난수 window.crypto.getRandomValues() 사용
 * 2. Zero-Transmission: 외부 서버 통신 없이 브라우저 내장 Web Crypto API(window.crypto.subtle) 로컬 연산
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// 브라우저 및 테스트 런타임 호환 Web Crypto 객체 참조
const getCrypto = () => {
  if (typeof window !== 'undefined' && window.crypto) {
    return window.crypto;
  }
  if (typeof globalThis !== 'undefined' && globalThis.crypto) {
    return globalThis.crypto;
  }
  throw new Error('Web Crypto API를 지원하지 않는 환경입니다.');
};

/**
 * 암호학적으로 안전한 Base32 비밀 키 생성 (기본 20바이트 = 160비트 = 32자 Base32)
 * RFC 4226 / RFC 6238 권장 HMAC-SHA1 키 길이 160비트
 * @param {number} byteLength - 비밀 키 바이트 길이 (기본값: 20바이트)
 * @returns {string} Base32 인코딩된 비밀 키
 */
export function generateSecret(byteLength = 20) {
  const crypto = getCrypto();
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToBase32(bytes);
}

/**
 * Uint8Array 바이트 배열을 Base32 문자열로 변환 (RFC 4648)
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToBase32(bytes) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Base32 문자열을 Uint8Array 바이트 배열로 디코딩 (RFC 4648)
 * @param {string} base32
 * @returns {Uint8Array}
 */
export function base32ToBytes(base32) {
  if (!base32 || typeof base32 !== 'string') {
    throw new Error('유효한 Base32 문자열이 아닙니다.');
  }

  // 공백, 하이픈 제거, 대문자 변환, 패딩('=') 제거
  const clean = base32.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < clean.length; i++) {
    const char = clean[i];
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) {
      throw new Error(`지원하지 않는 Base32 문자입니다: "${char}"`);
    }
    value = (value << 5) | val;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(bytes);
}

/**
 * 64-bit Big-Endian 8바이트 시간 카운터 버퍼 생성
 * @param {number|bigint} counter
 * @returns {ArrayBuffer}
 */
export function getCounterBuffer(counter) {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setBigUint64(0, BigInt(counter), false); // false = Big-Endian
  return buffer;
}

/**
 * RFC 6238 기반 6자리 TOTP 생성
 * @param {string} secret - Base32 비밀 키
 * @param {number|null} counter - 수동 카운터 (null일 경우 현재 시간 기준 계산)
 * @param {number} timeStep - 시간 단위(초) (기본값: 30)
 * @returns {Promise<string>} 6자리 OTP 문자열
 */
export async function generateTOTP(secret, counter = null, timeStep = 30) {
  const crypto = getCrypto();
  const currentCounter = counter !== null
    ? counter
    : Math.floor(Date.now() / 1000 / timeStep);

  const keyBytes = base32ToBytes(secret);

  // Web Crypto API: HMAC-SHA1 키 import (Zero-Transmission 로컬 연산)
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: { name: 'SHA-1' } },
    false,
    ['sign']
  );

  // 8바이트 Big-Endian 시간 카운터 버퍼
  const counterBuffer = getCounterBuffer(currentCounter);

  // HMAC-SHA1 서명 연산
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, counterBuffer);
  const hmac = new Uint8Array(signature);

  // Dynamic Truncation (RFC 4226 Section 5.3)
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % 1000000;
  return otp.toString().padStart(6, '0');
}

/**
 * 사용자 입력 OTP 검증
 * @param {string} token - 사용자가 입력한 6자리 코드
 * @param {string} secret - Base32 비밀 키
 * @param {object} [options]
 * @param {number} [options.window=1] - 허용 오차 스텝 (0: 현재만, 1: ±30초 허용)
 * @param {number} [options.timeStep=30] - 시간 스텝(기본 30초)
 * @returns {Promise<{valid: boolean, offset: number|null, message?: string}>}
 */
export async function verifyTOTP(token, secret, options = { window: 1, timeStep: 30 }) {
  const cleanToken = (token || '').trim();
  if (cleanToken.length !== 6 || !/^\d{6}$/.test(cleanToken)) {
    return { valid: false, offset: null, message: '6자리 숫자를 입력해 주세요.' };
  }

  const step = options.timeStep || 30;
  const currentCounter = Math.floor(Date.now() / 1000 / step);
  const windowSize = typeof options.window === 'number' ? options.window : 1;

  for (let offset = -windowSize; offset <= windowSize; offset++) {
    const expected = await generateTOTP(secret, currentCounter + offset, step);
    if (cleanToken === expected) {
      return {
        valid: true,
        offset,
        message: offset === 0 ? '정상 승인 (현재 주기)' : `시간 오차 허용 승인 (${offset > 0 ? '+30초' : '-30초'})`
      };
    }
  }

  return { valid: false, offset: null, message: 'OTP 코드가 일치하지 않습니다.' };
}

/**
 * 30초 주기 중 현재 주기의 남은 시간(초) 계산 (1 ~ 30)
 * @param {number} [timeStep=30] - 기본값 30
 * @returns {number} 남은 시간(초)
 */
export function getRemainingSeconds(timeStep = 30) {
  const epoch = Math.floor(Date.now() / 1000);
  const elapsed = epoch % timeStep;
  const remaining = timeStep - elapsed;
  return remaining === 0 ? timeStep : remaining;
}

/**
 * Google Authenticator 규격 otpauth:// URI 생성
 * @param {object} params
 * @param {string} params.issuer - 발급자 (예: KOPO-CyberSec)
 * @param {string} params.account - 계정명 (예: student@kopo.ac.kr)
 * @param {string} params.secret - Base32 비밀 키
 * @returns {string} otpauth URI
 */
export function generateOtpAuthUri({ issuer, account, secret }) {
  const cleanIssuer = (issuer || '').trim();
  const cleanAccount = (account || '').trim();
  const cleanSecret = (secret || '').trim().replace(/\s+/g, '');
  const encodedIssuer = encodeURIComponent(cleanIssuer);
  const encodedAccount = encodeURIComponent(cleanAccount);
  const encodedSecret = encodeURIComponent(cleanSecret);
  return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${encodedSecret}&issuer=${encodedIssuer}`;
}

/**
 * 1회용 백업 복구 코드 생성기 (기본 5개, 8자리 XXXX-XXXX 형식)
 * window.crypto.getRandomValues() 활용
 * @param {number} [count=5]
 * @returns {string[]}
 */
export function generateBackupCodes(count = 5) {
  const crypto = getCrypto();
  const chars = '0123456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  const codes = [];

  for (let i = 0; i < count; i++) {
    const randomBytes = new Uint8Array(8);
    crypto.getRandomValues(randomBytes);
    let code = '';
    for (let j = 0; j < 8; j++) {
      code += chars[randomBytes[j] % chars.length];
      if (j === 3) code += '-';
    }
    codes.push(code);
  }

  return codes;
}
