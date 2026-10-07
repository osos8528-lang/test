# Todo 실습의 기능 기준

교재는 Todo·날씨·게시판·자유 주제 중 한 가지를 선택하도록 안내합니다.
현재 프로젝트는 Todo를 선택했습니다. 아래 기능을 main.py와 tests/test_api.py로 구현·검증합니다.

| 요구사항 | 현재 구현 | 확인 방법 |
|---|---|---|
| DB 저장과 조회 | POST /todos, GET /todos | 새 항목 등록 후 동일 데이터 조회 |
| 제목·설명 검색 | GET /todos/search?q=... | 두 필드 검색, 특수문자와 공격 문자열의 문자 취급 |
| 관리자 인증과 삭제 | POST /admin/login, DELETE /admin/todos/{id} | 정상 로그인·삭제, 잘못된 토큰·만료·일반 권한 거부 |
| 차단 태그 제외 | GET /todos/filtered | spam/ad/private/temp 정확한 태그 제외 |

모델은 id, title, description, is_completed, created_at, tags를 가집니다.
개별 조회 GET /todos/{id}와 전체 교체 PUT /todos/{id}도 구현했습니다.
SQLite 파일명은 환경변수 DB_FILE로 지정하고, 기본값은 service.db입니다.
교재 프리셋의 todo.db와 이름은 다르지만 같은 저장 역할을 합니다.

관리자 비밀번호의 하드코딩 기본값은 사용하지 않습니다.
비밀번호는 무작위 salt와 PBKDF2-HMAC-SHA256으로 해시합니다.
부분 문자열 검색은 전체 스캔이며, 전체 서비스 속도나 운영 안전성을 보장하지 않습니다.
