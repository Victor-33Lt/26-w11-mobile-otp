import { useState, useEffect, useCallback, useRef } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import {
  ShieldCheck,
  Key,
  QrCode,
  RefreshCw,
  Copy,
  Check,
  Clock,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Smartphone,
  Server,
  Lock,
  History,
  LifeBuoy,
  WifiOff,
  Sparkles,
  ArrowRight,
  ShieldAlert
} from 'lucide-react';
import {
  generateSecret,
  generateTOTP,
  verifyTOTP,
  getRemainingSeconds,
  generateOtpAuthUri,
  generateBackupCodes
} from './utils/totp';
import './App.css';

export default function App() {
  // 1. 서비스 서버 시뮬레이터 상태
  const [issuer, setIssuer] = useState('KOPO-CyberSec');
  const [account, setAccount] = useState('student@kopo.ac.kr');
  const [secret, setSecret] = useState(() => generateSecret(20));
  const [backupCodes, setBackupCodes] = useState(() => generateBackupCodes(5));
  const [usedBackupCodes, setUsedBackupCodes] = useState([]);

  // 2. 모바일 인증기 & 타이머 상태
  const [currentOtp, setCurrentOtp] = useState('------');
  const [remainingSeconds, setRemainingSeconds] = useState(30);

  // 3. 검증기 상태
  const [inputOtp, setInputOtp] = useState('');
  const [allowSkew, setAllowSkew] = useState(true); // ±30초 시간 오차 허용 토글
  const [verificationResult, setVerificationResult] = useState(null);
  const [verificationLogs, setVerificationLogs] = useState([]);

  // 4. 백업 코드 입력 모달/탭 상태
  const [useBackupMode, setUseBackupMode] = useState(false);
  const [inputBackupCode, setInputBackupCode] = useState('');

  // 5. 복사 피드백 상태
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedOtp, setCopiedOtp] = useState(false);
  const [copiedUri, setCopiedUri] = useState(false);

  const inputRef = useRef(null);

  // 새 비밀 키 및 백업 코드 재발급
  const handleRegenerateSecret = useCallback(() => {
    try {
      const newSecret = generateSecret(20); // 32자 Base32
      setSecret(newSecret);
      setBackupCodes(generateBackupCodes(5));
      setUsedBackupCodes([]);
      setVerificationResult(null);
      setInputOtp('');
    } catch (err) {
      console.error('비밀 키 생성 실패:', err);
    }
  }, []);

  // 실시간 OTP 및 30초 카운트다운 타이머
  useEffect(() => {
    if (!secret) return;

    let isMounted = true;

    const updateOtpAndTimer = async () => {
      const remaining = getRemainingSeconds(30);
      setRemainingSeconds(remaining);

      try {
        const otp = await generateTOTP(secret);
        if (isMounted) {
          setCurrentOtp(otp);
        }
      } catch (err) {
        console.error('OTP 생성 중 오류:', err);
      }
    };

    // 즉시 1회 실행
    updateOtpAndTimer();

    // 1초 주기로 실시간 갱신
    const timerId = setInterval(updateOtpAndTimer, 1000);

    return () => {
      isMounted = false;
      clearInterval(timerId);
    };
  }, [secret]);

  // OTP 인증 검증 처리
  const handleVerify = async (e) => {
    if (e) e.preventDefault();
    if (!inputOtp || inputOtp.length !== 6) {
      setVerificationResult({
        success: false,
        message: '6자리 인증 코드를 정확히 입력하세요.'
      });
      return;
    }

    try {
      const res = await verifyTOTP(inputOtp, secret, {
        window: allowSkew ? 1 : 0,
        timeStep: 30
      });

      const nowStr = new Date().toLocaleTimeString('ko-KR', { hour12: false });
      const logItem = {
        id: Date.now(),
        time: nowStr,
        type: 'TOTP',
        code: inputOtp,
        success: res.valid,
        message: res.message || (res.valid ? '인증 성공' : '코드 불일치')
      };

      setVerificationResult({
        success: res.valid,
        message: res.valid
          ? `인증 성공: ${res.message}`
          : '인증 실패: 유효하지 않거나 만료된 OTP 코드입니다.',
        offset: res.offset
      });

      setVerificationLogs((prev) => [logItem, ...prev.slice(0, 7)]);
    } catch (err) {
      console.error('검증 에러:', err);
      setVerificationResult({
        success: false,
        message: '검증 처리 중 오류가 발생했습니다.'
      });
    }
  };

  // 비상 복구 백업 코드 검증 처리
  const handleVerifyBackup = (e) => {
    if (e) e.preventDefault();
    const clean = inputBackupCode.trim().toUpperCase();

    if (!clean) {
      setVerificationResult({
        success: false,
        message: '백업 복구 코드를 입력해 주세요.'
      });
      return;
    }

    const nowStr = new Date().toLocaleTimeString('ko-KR', { hour12: false });

    if (usedBackupCodes.includes(clean)) {
      const log = {
        id: Date.now(),
        time: nowStr,
        type: 'BACKUP',
        code: clean,
        success: false,
        message: '이미 사용된 1회용 백업 코드'
      };
      setVerificationResult({
        success: false,
        message: '이미 사용 완료된 1회용 복구 코드입니다.'
      });
      setVerificationLogs((prev) => [log, ...prev.slice(0, 7)]);
      return;
    }

    if (backupCodes.includes(clean)) {
      setUsedBackupCodes((prev) => [...prev, clean]);
      const log = {
        id: Date.now(),
        time: nowStr,
        type: 'BACKUP',
        code: clean,
        success: true,
        message: '1회용 백업 코드로 비상 인증 성공'
      };
      setVerificationResult({
        success: true,
        message: '비상 백업 코드로 성공적으로 인증되었습니다! (해당 코드는 소멸됨)'
      });
      setVerificationLogs((prev) => [log, ...prev.slice(0, 7)]);
      setInputBackupCode('');
    } else {
      const log = {
        id: Date.now(),
        time: nowStr,
        type: 'BACKUP',
        code: clean,
        success: false,
        message: '일치하지 않는 백업 코드'
      };
      setVerificationResult({
        success: false,
        message: '존재하지 않거나 유효하지 않은 백업 코드입니다.'
      });
      setVerificationLogs((prev) => [log, ...prev.slice(0, 7)]);
    }
  };

  // 클립보드 복사 헬퍼
  const copyToClipboard = (text, type) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    if (type === 'key') {
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    } else if (type === 'otp') {
      setCopiedOtp(true);
      setTimeout(() => setCopiedOtp(false), 2000);
    } else if (type === 'uri') {
      setCopiedUri(true);
      setTimeout(() => setCopiedUri(false), 2000);
    }
  };

  // OTP 자동 채우기 (테스트 편의 기능)
  const handleAutoFill = () => {
    if (currentOtp && currentOtp !== '------') {
      setInputOtp(currentOtp);
      if (inputRef.current) inputRef.current.focus();
    }
  };

  const otpAuthUri = secret
    ? generateOtpAuthUri({ issuer, account, secret })
    : '';

  // 프로그레스 바 비율 (0 ~ 100%)
  const progressPercent = Math.max(0, Math.min(100, (remainingSeconds / 30) * 100));

  // 긴박도에 따른 게이지 색상 결정
  const getProgressColor = () => {
    if (remainingSeconds <= 5) return 'var(--danger-color)';
    if (remainingSeconds <= 10) return 'var(--warning-color)';
    return 'var(--primary-color)';
  };

  return (
    <div className="app-container">
      {/* 🚀 상단 헤더 & 보안 상태 띠 */}
      <header className="header">
        <div className="header-brand">
          <div className="brand-icon-wrapper">
            <ShieldCheck className="brand-icon" size={30} />
          </div>
          <div>
            <h1 className="header-title">CyberOTP Studio</h1>
            <p className="header-subtitle">
              RFC 6238 표준 모바일 OTP (TOTP 2단계 인증) 웹 스튜디오
            </p>
          </div>
        </div>

        {/* 보안 특성 배지 목록 */}
        <div className="security-badges">
          <div className="badge-item badge-zero" title="외부 API 통신 없이 브라우저 subtle.crypto 내부에서만 암호화 연산">
            <WifiOff size={14} />
            <span>Zero-Transmission</span>
          </div>
          <div className="badge-item badge-crypto" title="예측 가능한 Math.random 대신 암호학적 난수 생성기 사용">
            <Lock size={14} />
            <span>crypto.getRandomValues</span>
          </div>
          <div className="badge-item badge-rfc" title="HMAC-SHA1 64-bit Big-Endian 동적 절단 표준 준수">
            <Sparkles size={14} />
            <span>RFC 6238 / 4226</span>
          </div>
        </div>
      </header>

      {/* 🖥️ 2단 메인 대시보드 */}
      <main className="dashboard-grid">
        {/* ========================================================= */}
        {/* [좌측 패널] 서비스 서버 시뮬레이터 (2FA 발급 및 QR 연동) */}
        {/* ========================================================= */}
        <section className="panel server-panel">
          <div className="panel-header">
            <div className="panel-title-group">
              <Server className="panel-icon text-indigo" size={22} />
              <div>
                <h2 className="panel-title">서비스 서버 시뮬레이터</h2>
                <p className="panel-desc">2단계 인증 활성화 및 OTP 시크릿 발급 서버</p>
              </div>
            </div>
            <button
              type="button"
              onClick={handleRegenerateSecret}
              className="btn btn-secondary btn-sm"
              title="새로운 암호학적 Base32 비밀 키 발급"
            >
              <RefreshCw size={15} />
              <span>새 비밀 키 발급</span>
            </button>
          </div>

          <div className="panel-body">
            {/* 발급 정보 입력 폼 */}
            <div className="form-row">
              <div className="form-group flex-1">
                <label className="form-label" htmlFor="issuer-input">
                  발급자 (Issuer)
                </label>
                <input
                  id="issuer-input"
                  type="text"
                  className="input-text"
                  value={issuer}
                  onChange={(e) => setIssuer(e.target.value)}
                  placeholder="예: KOPO-CyberSec"
                />
              </div>
              <div className="form-group flex-1">
                <label className="form-label" htmlFor="account-input">
                  사용자 계정 (Account)
                </label>
                <input
                  id="account-input"
                  type="text"
                  className="input-text"
                  value={account}
                  onChange={(e) => setAccount(e.target.value)}
                  placeholder="예: student@kopo.ac.kr"
                />
              </div>
            </div>

            {/* Base32 비밀 키 표시 카드 */}
            <div className="secret-card">
              <div className="secret-header">
                <div className="secret-title">
                  <Key size={16} className="text-indigo" />
                  <span>Base32 보안 비밀 키 (Secret Key)</span>
                </div>
                <button
                  type="button"
                  onClick={() => copyToClipboard(secret, 'key')}
                  className="btn-icon"
                  title="비밀 키 복사"
                >
                  {copiedKey ? <Check size={16} className="text-emerald" /> : <Copy size={16} />}
                  <span>{copiedKey ? '복사됨!' : '복사'}</span>
                </button>
              </div>
              <div className="secret-code-box" title="RFC 4648 Base32 인코딩 (160-bit 엔트로피)">
                <code>{secret || '키 생성 중...'}</code>
              </div>
              <p className="secret-tip">
                * <code>window.crypto.getRandomValues()</code> 기반 암호학적 난수로 생성된 20바이트(160비트) 보안 키입니다.
              </p>
            </div>

            {/* QR 코드 등록 섹션 */}
            <div className="qr-section">
              <div className="qr-box-wrapper">
                <div className="qr-frame">
                  {otpAuthUri ? (
                    <QRCodeSVG
                      value={otpAuthUri}
                      size={180}
                      level="M"
                      includeMargin={false}
                    />
                  ) : (
                    <div className="qr-placeholder">QR 생성 중...</div>
                  )}
                </div>
                <div className="qr-instructions">
                  <div className="qr-instruct-title">
                    <Smartphone size={18} className="text-indigo" />
                    <span>스마트폰 Authenticator 등록</span>
                  </div>
                  <ol className="qr-steps">
                    <li>스마트폰에서 <strong>Google Authenticator</strong> 또는 <strong>Microsoft Authenticator</strong>를 엽니다.</li>
                    <li><strong>[+]</strong> 버튼을 누르고 <strong>[QR 코드 스캔]</strong>을 선택합니다.</li>
                    <li>좌측의 QR 코드를 스캔하면 계정이 등록됩니다.</li>
                  </ol>
                  <div className="uri-copy-row">
                    <button
                      type="button"
                      onClick={() => copyToClipboard(otpAuthUri, 'uri')}
                      className="btn btn-outline btn-xs"
                      title="otpauth:// URI 주소 복사"
                    >
                      <QrCode size={13} />
                      <span>{copiedUri ? 'URI 복사됨' : 'otpauth:// URI 복사'}</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* 1회용 백업 복구 코드 아코디언/섹션 */}
            <div className="backup-section">
              <div className="backup-header">
                <div className="backup-title">
                  <LifeBuoy size={16} className="text-amber" />
                  <span>비상 1회용 백업 복구 코드 (Emergency Backup Codes)</span>
                </div>
                <span className="backup-count">
                  {5 - usedBackupCodes.length}/5 사용 가능
                </span>
              </div>
              <div className="backup-codes-grid">
                {backupCodes.map((code, idx) => {
                  const isUsed = usedBackupCodes.includes(code);
                  return (
                    <div
                      key={idx}
                      className={`backup-code-pill ${isUsed ? 'used' : ''}`}
                      title={isUsed ? '이미 사용된 코드' : '1회용 비상 복구 코드'}
                    >
                      <span>{code}</span>
                      {isUsed && <span className="used-badge">사용됨</span>}
                    </div>
                  );
                })}
              </div>
              <p className="backup-note">
                스마트폰 분실 시 우측 검증기에서 1회에 한해 긴급 인증 수단으로 사용 가능합니다.
              </p>
            </div>
          </div>
        </section>

        {/* ========================================================= */}
        {/* [우측 패널] 모바일 인증기 & 코드 검증기 (Authenticator & Verifier) */}
        {/* ========================================================= */}
        <section className="panel client-panel">
          <div className="panel-header">
            <div className="panel-title-group">
              <Smartphone className="panel-icon text-cyan" size={22} />
              <div>
                <h2 className="panel-title">모바일 인증기 & 코드 검증기</h2>
                <p className="panel-desc">실시간 동기화 OTP 확인 및 서비스 로그인 검증</p>
              </div>
            </div>
            <div className="sync-status" title="현재 시스템 시각과 정확히 동기화">
              <span className="live-dot"></span>
              <span>실시간 동기화</span>
            </div>
          </div>

          <div className="panel-body">
            {/* 30초 카운트다운 타이머 & 실시간 OTP 번호 카드 */}
            <div className="otp-live-card">
              <div className="otp-live-header">
                <div className="otp-live-label">
                  <Clock size={16} />
                  <span>현재 30초 주기 예상 OTP</span>
                </div>
                <div className="timer-badge" style={{ color: getProgressColor() }}>
                  <span className="timer-seconds">{remainingSeconds}</span>
                  <span className="timer-unit">초 남음</span>
                </div>
              </div>

              {/* 30초 프로그레스 바 */}
              <div className="progress-track" role="progressbar" aria-valuenow={remainingSeconds} aria-valuemin={1} aria-valuemax={30}>
                <div
                  className="progress-fill"
                  style={{
                    width: `${progressPercent}%`,
                    backgroundColor: getProgressColor()
                  }}
                ></div>
              </div>

              {/* 6자리 큰 글씨 OTP 표시 */}
              <div className="otp-display-group">
                <div className="otp-number-wrapper" onClick={handleAutoFill} title="클릭 시 검증창에 자동 입력">
                  <span className="otp-part">{currentOtp.slice(0, 3)}</span>
                  <span className="otp-separator">·</span>
                  <span className="otp-part">{currentOtp.slice(3, 6)}</span>
                </div>
                <div className="otp-action-buttons">
                  <button
                    type="button"
                    onClick={() => copyToClipboard(currentOtp, 'otp')}
                    className="btn btn-secondary btn-sm"
                    title="현재 6자리 번호 복사"
                  >
                    {copiedOtp ? <Check size={14} className="text-emerald" /> : <Copy size={14} />}
                    <span>{copiedOtp ? '복사 완료' : '복사'}</span>
                  </button>
                  <button
                    type="button"
                    onClick={handleAutoFill}
                    className="btn btn-outline btn-sm"
                    title="검증 입력창에 즉시 자동 입력"
                  >
                    <ArrowRight size={14} />
                    <span>입력창 채우기</span>
                  </button>
                </div>
              </div>

              <div className="otp-match-hint">
                <Smartphone size={14} className="text-cyan" />
                <span>스마트폰 Google Authenticator 화면에 뜬 번호와 정확히 일치합니다.</span>
              </div>
            </div>

            {/* 2단계 인증 검증 폼 */}
            <div className="verification-card">
              <div className="verify-tab-header">
                <button
                  type="button"
                  className={`tab-btn ${!useBackupMode ? 'active' : ''}`}
                  onClick={() => {
                    setUseBackupMode(false);
                    setVerificationResult(null);
                  }}
                >
                  <Smartphone size={15} />
                  <span>6자리 OTP 검증</span>
                </button>
                <button
                  type="button"
                  className={`tab-btn ${useBackupMode ? 'active' : ''}`}
                  onClick={() => {
                    setUseBackupMode(true);
                    setVerificationResult(null);
                  }}
                >
                  <LifeBuoy size={15} />
                  <span>백업 코드로 검증</span>
                </button>
              </div>

              {!useBackupMode ? (
                /* 표준 6자리 OTP 입력 폼 */
                <form onSubmit={handleVerify} className="verify-form">
                  <div className="form-group">
                    <label className="form-label" htmlFor="otp-input">
                      스마트폰 또는 위의 6자리 인증 번호 입력
                    </label>
                    <div className="input-with-button">
                      <input
                        id="otp-input"
                        ref={inputRef}
                        type="text"
                        inputMode="numeric"
                        maxLength={6}
                        autoComplete="one-time-code"
                        className="input-code"
                        placeholder="000000"
                        value={inputOtp}
                        onChange={(e) => {
                          const val = e.target.value.replace(/\D/g, '').slice(0, 6);
                          setInputOtp(val);
                        }}
                      />
                      <button
                        type="submit"
                        className="btn btn-primary"
                        disabled={inputOtp.length !== 6}
                      >
                        <ShieldCheck size={18} />
                        <span>인증 확인</span>
                      </button>
                    </div>
                  </div>

                  {/* 시간 오차 허용 옵션 */}
                  <div className="options-row">
                    <label className="checkbox-label" title="클라이언트와 서버 시계가 30초 가량 차이나도 앞뒤 1주기를 허용">
                      <input
                        type="checkbox"
                        checked={allowSkew}
                        onChange={(e) => setAllowSkew(e.target.checked)}
                      />
                      <span>시간 오차(±30초 Drift) 허용 (권장)</span>
                    </label>
                  </div>
                </form>
              ) : (
                /* 비상 백업 코드 입력 폼 */
                <form onSubmit={handleVerifyBackup} className="verify-form">
                  <div className="form-group">
                    <label className="form-label" htmlFor="backup-input">
                      비상 1회용 복구 코드 입력 (예: XXXX-XXXX)
                    </label>
                    <div className="input-with-button">
                      <input
                        id="backup-input"
                        type="text"
                        maxLength={9}
                        className="input-code backup-input-style"
                        placeholder="XXXX-XXXX"
                        value={inputBackupCode}
                        onChange={(e) => setInputBackupCode(e.target.value.toUpperCase())}
                      />
                      <button
                        type="submit"
                        className="btn btn-warning"
                        disabled={!inputBackupCode.trim()}
                      >
                        <LifeBuoy size={18} />
                        <span>비상 인증</span>
                      </button>
                    </div>
                  </div>
                </form>
              )}

              {/* 검증 결과 명확한 판정 배지 */}
              {verificationResult && (
                <div
                  className={`result-alert ${
                    verificationResult.success ? 'alert-success' : 'alert-danger'
                  }`}
                  role="alert"
                >
                  <div className="alert-icon">
                    {verificationResult.success ? (
                      <CheckCircle2 size={24} />
                    ) : (
                      <XCircle size={24} />
                    )}
                  </div>
                  <div className="alert-content">
                    <div className="alert-title">
                      {verificationResult.success ? '인증 성공 (Verified)' : '인증 실패 (Failed)'}
                    </div>
                    <div className="alert-message">{verificationResult.message}</div>
                  </div>
                </div>
              )}
            </div>

            {/* 최근 인증 검증 이력 (로그) */}
            <div className="audit-card">
              <div className="audit-header">
                <div className="audit-title">
                  <History size={16} />
                  <span>인증 시도 검증 이력 (최근 로그)</span>
                </div>
                <span className="audit-count">{verificationLogs.length}건 기록</span>
              </div>
              {verificationLogs.length === 0 ? (
                <div className="audit-empty">
                  아직 인증 시도 이력이 없습니다. 번호를 입력하고 [인증 확인]을 눌러보세요.
                </div>
              ) : (
                <ul className="audit-list">
                  {verificationLogs.map((log) => (
                    <li key={log.id} className={`audit-item ${log.success ? 'log-success' : 'log-fail'}`}>
                      <span className="log-time">{log.time}</span>
                      <span className={`log-badge ${log.success ? 'badge-ok' : 'badge-err'}`}>
                        {log.success ? '성공' : '실패'}
                      </span>
                      <span className="log-type">[{log.type}]</span>
                      <span className="log-code">{log.code}</span>
                      <span className="log-msg">{log.message}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </section>
      </main>

      {/* 🛡️ 하단 사이버보안 체크포인트 설명 푸터 */}
      <footer className="footer">
        <div className="footer-content">
          <div className="footer-col">
            <h3 className="footer-heading">
              <ShieldAlert size={16} className="text-indigo" />
              <span>보안 원칙 1: 암호학적 난수 생성</span>
            </h3>
            <p className="footer-text">
              <code>Math.random()</code>은 선형 합동 생성기(LCG) 기반으로 다음 난수를 역추적할 수 있어 비밀 키로 부적합합니다.
              본 시스템은 <code>window.crypto.getRandomValues()</code>로 시스템 엔트로피를 직접 수집합니다.
            </p>
          </div>
          <div className="footer-col">
            <h3 className="footer-heading">
              <WifiOff size={16} className="text-cyan" />
              <span>보안 원칙 2: Zero-Transmission (무전송)</span>
            </h3>
            <p className="footer-text">
              비밀 키와 HMAC-SHA1 연산은 외부 서버로 전송되지 않고 브라우저 내장 <code>window.crypto.subtle</code>로만 수행됩니다.
              개발자 도구(F12)의 Network 탭을 확인하면 키가 외부로 유출되지 않음을 직접 확인할 수 있습니다.
            </p>
          </div>
          <div className="footer-col">
            <h3 className="footer-heading">
              <AlertCircle size={16} className="text-emerald" />
              <span>RFC 6238 표준 원리</span>
            </h3>
            <p className="footer-text">
              공유 비밀 키(K)와 30초 단위 카운터(T)를 결합하여 HMAC-SHA1 서명을 생성한 후, 마지막 바이트의 하위 4비트로 4바이트를 동적 절단하여 6자리 숫자를 도출합니다.
            </p>
          </div>
        </div>
        <div className="footer-bottom">
          <span>한국폴리텍대학 강서캠퍼스 사이버보안과 실습용 WebOTP 엔진</span>
          <span>RFC 6238 · RFC 4226 · RFC 4648 표준 준수</span>
        </div>
      </footer>
    </div>
  );
}
