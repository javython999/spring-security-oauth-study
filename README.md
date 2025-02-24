# Spring Security Fundamentals
## 초기화 과정 이해 - SecurityBuilder / SecurityConfigurer
### 개념 및 구조 이해
* SecurityBuilder는 빌더 클래스로서 웹 보안을 구성하는 빈 객체와 설정 클래스들을 생성하는 역할을 하며 WebSecurity, HttpSecurity가 있다.
* SecurityConfigurer는 Http 요청과 관련된 보안처리를 담당하는 필터들을 생성하고 여러 초기화 설정에 관여한다.
* SecurityBuilder는 SecurityConfigurer를 포함하고 있으며 인증 및 인가 초기화 작업은 SecurityConfigurer에 의해 진행된다.

### 자동설정에 의한 초기화 과정 이해
1. SpringWebMvcImportSelector 로드 (WebMvcSecurityConfiguration)
2. SecurityFilterAutoConfiguration 로드 (DelegatingFilterProxyRegistrationBean 생성 - DelegatingFilterProxy 등록("springSecurityFilterChain" 이름의 빈을 검색))
3. WebMvcSecurityConfiguration 로드 
   * AuthenticationPrincipalArgumentResolver 생성 - @AuthenticationPrincipal로 Principal 객체 바인딩
   * CurrentSecurityContextArgumentResolver 생성
   * CsrfTokenArgumentResolver 생성
4. HttpSecurity: 공통 설정 클래스와 필터들을 생성하고 최종적으로 SecurityFilterChain 빈 반환 
5. SpringBootWebSecurityConfiguration
6. WebSecurityConfiguration

* WebSecurity는 설정클래스에서 정의한 SecurityFilterChain 빈을 SecurityBuilder에 저장한다.
* WebSecurity가 build()를 실행하면 SecurityBuilder에서 SecurityFilterChain을 꺼내어 FilterChainProxy 생성자에게 전달한다.

#### 사용자 정의 설정 클래스
* 설정 클래스를 커스텀하게 생성하기 때문에 SpringBootWebSecurityConfiguration의 SecurityFilterChainConfiguration 클래스가 구동되지 않는다.
* 사용자 정의 클래스 생성시 SecurityFilterChain과 WebSecurityConfigurationAdapter 두 가지 방식 모두 설정할 수 없으며 하나만 정의해야 한다.

### AuthenticationEntryPoint 이해
* Spring Security는 초기화때 인증방식 2개(formLogin, httpBasic)를 설정한다.
* 인증 예외 발생시 `ExceptionHandlingConfigurer`가 `AuthenticationEntryPoint` 클래스를 통해서 처리한다.
* 커스텀 엔트리포인트가 생성되면 formLogin, httpBasic의 defaultEntryPoint 보다 우선 적용된다.

## 시큐리티 인증 및 인가 흐름 요약
* 인증
```mermaid
sequenceDiagram
    사용자 요청->>DelegatingFilterProxy: 사용자 요청
    DelegatingFilterProxy ->> FilterChainProxy: springSecurityFilterChain 빈을 찾아 요청 위임
    FilterChainProxy ->> AuthenticationFilter: AuthenticationFilter에게 인증 위임
    AuthenticationFilter ->> Authentication: 사용자로부터 받은 정보를 Authentication에 저장 
    AuthenticationFilter ->> AuthenticationManager: Authentication 인증을 AuthenticationManager에게 위임
   
    AuthenticationManager ->> AuthenticationProvider: 인증처리를 할 수 있는 클래스를 찾고 Authentication 인증을 위임 
    AuthenticationProvider ->> UseDetailService: 유저 정보 조회
    UseDetailService ->> UserDetails: 유저 정보가 있는 경우 UserDetails 생성
    UserDetails ->> AuthenticationProvider: UserDetails 반환
    AuthenticationProvider ->> AuthenticationFilter: Authenticatio 객체를 만들고 반환
    AuthenticationFilter ->> SecurityContext: SecurityContext에 인증 정보 저장
```

* 인가
```mermaid
sequenceDiagram
    사용자 요청 ->> DelegatingFilterProxy: 사용자 요청
    DelegatingFilterProxy ->> FilterChainProxy: springSecurityFilterChain 빈을 찾아 요청 위임
    FilterChainProxy ->> AuthenticationFilter: AuthenticationFilter에게 인증 위임
    AuthenticationFilter ->> ExceptionTranslationFilter: 인증/인가 예외 처리
    ExceptionTranslationFilter ->> FilterSecurityInterceptor: 인가 처리
    FilterSecurityInterceptor ->> AccessDecisionManager: 인가 처리 위임
    AccessDecisionManager ->> AccessDecisionVoter: 인가 판단
    AccessDecisionVoter ->> AccessDecisionManager: 인가 결과 반환
    AccessDecisionManager ->> ExceptionTranslationFilter: 인증/인가 예외 처리
```

## Http Basic 인증
```mermaid
sequenceDiagram
   Client ->> Server: 인증정보 없이 접속
   Server ->> Client: 401 Unauthorized 응답 (헤더에 realm과 인증방법)
   Client ->> Server: Base64로 인코딩하고 Authorization 헤더에 담아 요청
   Server ->> Client: 200 Ok 응답
```
* base64 인코딩된 값은 쉽게 디코딩이 가능하기 때문에 인증정보가 노출된다.
* Http Basic 인증은 반드시 HTTPS와 같이 TLS 기술과 함께 사용해야 한다.

### HttpBasicConfigurer
* HttpBasic 인증에 대한 초기화를 진행하며 속성들에 대한 기본값들을 설정한다.
* 기본 AuthenticationEntryPoint는 BasicAuthenticationEntryPoint다.
* 필터는 BasicAuthenticationFilter를 사용한다.

### BasicAuthenticationFilter
* 이 필터는 기본 인증 서비스를 제공하는 데 사용된다.
* BasicAuthenticationConverter를 사용해서 요청 헤더에 기술된 인증정보의 유효성을 체크하며 Base64 인코딩된 username과 password를 추출한다.
* 인증이 성공하면 Authentication이 SecurityContext에 저장되고 인증이 실패하면 Basic 인증을 통해 다시 인증하라는 메시지를 표시하는 BasicAuthenticationEntryPoint가 호출된다.
* 인증 이후 세션을 사용하는 경우와 사용하지 않는 경우에 따라 처리되는 흐름에 차이가 있다. 세션을 사용하는 경우 매 요청 마다 인증과정을 거치지 않으나 세션을 사용하지 않는 경우 매 요청마다 인증과정을 거쳐야 한다.

### API
```java
protected void configure(final HttpSecurity http) throws Exception {
    http.authorizeRequests()
         .anyRequest().authenticated()
            .and()
            .httpBasic()
            .authenticationEntryPoint(new CustomAuthenticationEntryPoint());
}
```
## Cors 이해
Cross-Origin Resource Sharing, 교차 출처 리소스 공유
* HTTP 헤더를 사용하여, 한 출처에서 실행 중인 웹 애플리케이션이 다른 출처의 선택한 자원에 접근할 수 있는 권한을 부여하도록 브라우저에 알려주는 체제
* 웹 애플리케이션이 리소스가 자신의 출처와 다를 때 브라우저는 요청 헤더에 Origin 필드에 요청을 출처를 함께 담아 교차 출처 HTTP 요청을 실행한다.
* 출처를 비교하는 로직은 서버에 구현된 스펙이 아닌 브라우저에 구현된 스펙 기준으로 처리되며 브라우저는 클라이언트의 요청 헤더와 서버의 응답헤더를 비교해서 최종 응답을 결정한다.
* 두 개의 출처를 비교하는 방법은 URL의 구성요소중 Protocol, Host, Port 이 세가지가 동일한지 확인하면 되고 나머지는 틀려도 상관없다.

### Simple Request
* 예비 요청(Preflight) 과정없이 바로 서버에 본 요청을 한 후, 서버가 응답 헤더에 Access-Control-Allow-Origin과 같은 값을 전송하면 브라우저가 서로 비교후 CORS 정책 위반여부를 검사하는 방식
* 제약사항
  * GET, POST, HEAD 중의 한가지 Method를 사용해야 한다.
  * 헤더는 Accept, Accept-Language, Content-Language, Content-Type, DPR, Downlink, Save-Data, Viewport-Width width만 가능하고 Custom Header는 허용되지 않는다.
  * Content-type은 application/x-www-form-urlencoded, multipart/form-data, text/plain만 가능하다.

```mermaid
sequenceDiagram
    Javascript ->> Browser: fetch()
    Browser ->> Server: GET /resource
    Server ->> Browser: 200 Ok resource Access-Control-Allow-Origin:*
    Browser ->> Javascript: Promice.then
```

### Preflight Request
* 브라우저는 요청을 한번에 보내지 않고, 예비요청과 본요청으로 나누어 서버에 전달하는데 브라우저가 예비요청을 보내는 것을 Preflight라고 하고 OPTIONS 메소드가 사용된다.
* 예비요청의 역할은 본 요청을 보내기 전에 브라우저 스스로 안전한 요청인지 확인하는 것으로 요청 사앙이 SimpleRequest에 해당하지 않을 경우 브라우저가 Preflight Request를 실행한다.

```mermaid
sequenceDiagram
    Javascript ->> Browser: fetch()
    Browser ->> Server: [예비요청] OPTIONS /resource Origin:https://security.io
    Server ->> Browser: 200 OK Access-Control-Allow-Origin:*
   Browser ->> Server: [본요청] OPTIONS /resource Origin:https://security.io
   Server ->> Browser: 200 OK
   Browser ->> Javascript: Promice.then
```

### 동일 출처 기준
scheme, host, port가 동일한 경우 동일 출처로 판단.

### CORS 해결 - 서버에서 Access-Control-Allow-* 세팅
* Access-Control-Allow-Origin - 헤더에 작성된 출처만 브라우저가 리소스에 접근할 수 있도록 허용한다.
* Access-Control-Allow-Methods - preflight request에 대한 응답으로 실제 요청 중에 사용할 수있는 메서드를 나타낸다.
  * 기본값은 GET, POST, HEAD, OPTIONS, *
* Access-Control-Allow-Headers - preflight request에 대한 응답으로 실제 요청 중에 사용할 수 있는 헤더 필드 이름을 나타낸다.
* Access-Control-Allow-Credentials - 실제 요청에 쿠키나 인증 등의 사용자 자격 증명이 포함될 수 있음을 나타낸다. Client의 credentials:include일 경우 true 필수
* Access-Control-Max-Age - preflight 요청 결과를 캐시 할 수 있는 시간을 나타내는 것으로 해당 시간동안은 preflight 요청을 다시 하지 않게 된다.

### CorsConfigurer
* Spring Security 필터 체인에 CorsFilter를 추가한다.
* corsFilter라는 이름의 bean이 제공되면 해당 CorsFilter가 사용된다.
* corsFilter라는 이름의 bean이 없고 CorsConfigurationSource 빈이 정의된 경우 해당 CorsConfiguration이 사용된다.
* CorsConfigurationSource 빈이 정의되어 있지 않은 경우 Spring MVC가 클래스 경로에 있으면 HandlerMappingIntrospector가 사용된다.

### CorsFilter
* Cors 예비 요청을 처리하고 Cors 단순 및 본 요청을 가로채고, 제공된 CorsConfigurationSource를 통해 일치된 정책에 따라 Cors 응답 헤더와 같은 응답을 업데이트하기 위한 필터이다.
* Spring MVC Java 구성과 Spring MVC XML 네임스페이스에서 Cors를 구성하는 대안이라 볼 수있다 (예: @CorsOrigin)
* 스프링 웹에 의존하는 응용 프로글매이나 java.servlet에서 Cors 검사를 수행해야 하는 보안 제약 조건에 유용한 필터이다.

### API

```java
import java.beans.BeanProperty;

@Override
protected void configure(final HttpSecurity http) throws Exception {
   http.authorizeRequests()
           .anyRequest().authenticated()
           .and();
   http.cors().configurationSource(corsConfigurationSource());
}

@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.addAllowedOrigin("*");
    configuration.addAllowedMethod("*");
    configuration.addAllowedHeader("*");
    configuration.setAllowCredintials(true);
    configuration.setMaxAge(3600L);
    
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```
# OAuth 2.0 용어 이해
## OAuth 2.0
* `O`pen + `Auth`orization
* OAuth 2.0 인가 프레임워크는 애플리케이션이 사용자 대신하여 사용자의 자원에 대한 제한된 액세스를 얻기 위해 승인 상호 작용을 함으로써 애플리케이션이 자체적으로 액세스 권한을 얻도록 한다.
* 즉 사용자가 속한 사이트의 보호된 자원에 대하여 애플리케이션의 접근을 허용하도록 승인하는 것을 의미한다.
* Delegated authorization framework - 위임 인가 프레임워크

## OAuth2 오픈소스 keyCloak 
### keycloak
* ID 및 접근 관리를 지원하는 인가서버 오픈 소스로 사용자 연합, 강력한 인증, 사용자 관리, 세분화된 권한 부여 등을 제공한다.

## OAuth 2.0 Roles 이해
OAuth 2.0 메커니즘은 다음 네가지 종류의 역할을 담당하는 주체들에 의해 이루어지는 권한 부여 체계이다.

1. Resource Owner(자원 소유자)
   * 보호된 자원에 대한 접근 권한을 부여할 수 있는 주체, 사용자로서 계정의 일부에 대한 접근 권한을 부여하는 사람
   * 사용자를 대신하여 작동하려는 모든 클라이언트는 먼저 사용자의 허가를 받아야 한다.

2. Resource Server(보호자원서버)
   * 타사 애플리케이션에서 접근하는 사용자의 자원이 포함된 서버를 의미한다.
   * 액세스 토큰을 수락 및 검증할 수 있어야 하며 권한 체계에 따라 요청을 승인할 수 있어야 한다.

3. Authorization Server(인가서버)
   * 클라이언트가 사용자 계정에 대한 동의 및 접근을 요청할 때 상호작용하는 서버로서 클라이언트의 권한 부여 요청을 승인하거나 거부하는 서버
   * 사용자가 클라이언트에게 권한 부여 요청을 승인한 후 access token을 클라이언트에게 부여하는 역할

4. Client(클라이언트)
   * 사용자를 대신하여 권한을 부여받아 사용자의 리소스에 접근하려는 애플리케이션
   * 사용자를 권한 부여 서버로 안내하거나 사용자의 상호 작용 없이 권한 부여 서버로부터 직접 권한을 얻을 수 있다.


```mermaid
sequenceDiagram
    Resource Owner ->> Client: 권한 부여 요청 및 승인
    Client ->> Resource Owner: 권한 부여 요청 및 승인
    Client ->> Authorization Server: access token 요청
    Authorization Server ->> Client: access token 발행
    Client ->> Resource Server: 리소스 요청 with access token
    Resource Server ->> Authorization Server: access token 검증
```

### OAuth 2.0 Client Types
* 개요
  * 인증 서버에서 클라이어트를 등록할 때 클라이언트 자격 증명인 클라이언트 아이디와 클라이언트 암호를 받는다.
  * 클라이언트 암호는 비밀이고 그대로 유지되어야 하는 반면 클라이언트 아이디는 공개이다.
  * 이 자격 증명은 인증서버에 대한 클라이언트 ID를 증명한다.

* 기밀 클라이언트 (Confidential Clients)
  * 기밀 클라이언트는 client_secret의 기밀성을 유지할 수 있는 클라이언트를 의미한다.
  * 일반적으로 사용자가 소스 코드에 액세스할 수 없는 서버에서 실행되는 응용 프로그램으로 .NET, Java, PHP 및 Node JS와 같은 서버 측 언어로 작성된다.
  * 이러한 유형의 애플리케이션은 대부분 웹 서버에서 실행되기 때문에 일반적으로 "웹앱" 이라고 한다.

* 공개 클라이언트 (Public Clients)
  * 공개 클라이언트는 client_secret의 기밀을 유지할 수 없으므로 이러한 앱에는 secret의 사용되지 않는다.
  * 브라우저에서 실행되는 Javascript 애플리케이션, Android, iOS 모바일 앱, 데스크톱에서 실행되는 응용프래그램 등이 있다.
  * 서버측이 아닌 리소스 소유자가 사용하는 장치에서 실행되는 모든 클라이언트는 공개클라이언트로 간주되어야 한다.

### Public
* front channel
```mermaid
sequenceDiagram
    Client ->> AuthServer: request authorization
    AuthServer ->> Client: access token
```
* back channel
```mermaid
sequenceDiagram
```

### Confidential
* front channel
```mermaid
sequenceDiagram
    Client ->> AuthServer: request authorization
    AuthServer ->> Client: redirect with code
```
* back channel
```mermaid
sequenceDiagram
    Client ->> AuthServer: send code
    AuthServer ->> Client: access token
```

### OAuth 2.0 Token Types
1. Access Token
   * 클라이언트에서 사용자의 보호된 리소스에 접근하기 위해 사용하는 일종의 자격 증명으로서 역할을 하며 리소스 소유자가 클라이언트에게 부여한 권한 부여의 표현이다.
   * 일반적으로 JWT(Json Web Token) 형식을 취하지만 사양에 따라 그럴 필요는 없다.
   * 토큰에는 해당 액세스 기간, 범위 및 서버에 필요한 기타 정보가 있다.
   * 타입에는 식별자 타입 (Identifier Type)과 자체 포함타입 (Self-contained Type)이 있다.

2. Refresh Token
   * 액세스 토큰이 만료된 후 새 액세스 토큰을 얻기 위해 클라이언트 응용 프로그램에서 사용하는 자격 증명
   * 액세스 토큰이 만료되는 경우 클라이언트는 권한 부여 서버로 인증하고 Refresh Token을 전달한다.
   * 인증 서버는 Refresh Token의 유효성을 검사하고 새 액세스 토큰을 발급한다.
   * Refresh Token은 액세스 토큰과 달리 권한 서버 토큰 엔드포인트에만 보내지고 리소스 서버에는 보내지 않는다.

3. ID Token
4. Authorization Code
   * 권한 부여 코드 흐름에서 사용되며 이 코드는 클라이언트가 액세스 토큰과 교활할 임시 코드
   * 사용자가 클라이언트가 요청하는 정보를 확인하고 인가 서버로부터 리다이렉트 되어 받아온다.

### Access Token 유형
* 식별자 타입 (Identifier Type)
  * 인가 서버는 데이터 저장소에 토큰의 내용을 저장하고 이 토큰에 대한 고유 식별자만 클라이언트에 다시 발행한다.
  * 이 토큰을 수신하는 API는 토큰의 유효성을 검사하기 위해 인가서버에 대한 back channel 통신을 열고 DB를 조회해야 한다.

* 자체 포함 타입 (Self Contained Type)
  * JWT 토큰 형식으로 발급되며 클레임 및 만료가 있는 보호된 데이터 구조이다.
  * 리소스 서버 API가 검증 키 등의 핵심 자료에 대해 알게 되면 발급자와 통신할 필요 없이 자체 포함된 토큰의 유효성을 검사할 수 있다.
  * 특정한 암호화 알고리즘에 의해 개인키로 서명되고 공개키로 검증할 수 있으며 만료될 때까지 유효하다.

# OAuth 2.0 권한부여 유형
## OAuth 2.0 Grant Types 개요
### 권한 부여 유형
* 권한 부여란 클라이언트가 사용자를 대신해서 사용자의 승인하에 인가서버로부터 권한을 부여 받는 것을 의미한다.
* OAuth 2.0 메커니즘은 아래와 같은 권한 부여 유형들을 지원하고 있으며 일부는 Deprecated 되었다.

1. Authorization Code Grant Type
   * 권한 부여 타입, 서버 사이드 애플리케이션, 보안에 가장 안전한 유형
2. Implicit Grant Type (Deprecated)
   * 암시적 부여 타입, 공개 클라이언트 애플리케이션, 보안에 취약
3. Resource Owner Password Credentials Grant Type (Deprecated)
   * 리소스 사용자 비밀번호 자격증명 부여 타입, 서버 애플리케이션, 보안에 취약
4. Client Credentials Grant Type
   * 클라이언트 자격 증명 권한 부여 타입, UI or 화면이 없는 서버 애플리케이션
5. Refresh Token Grant Type
   * 새로고침 토큰 부여 타입, Authorization Code, Resource Owner Password Type에서 지원
6. PKCE-enhanced Authorization Code Grant Type
   * PKCE 권한 코드 부여 타입, 서버 사이드 애플리케이션, 공개 클라이언트 애플리케이션

* 권한 부여 흐름 선택 기준
```mermaid
flowchart LR
   공개_클라이언트인가? --예--> 클라이언트가_SPA_or_네이티브_앱? --네이티브--> Authorization_Code_with_PKCE
   클라이언트가_SPA_or_네이티브_앱? --SPA--> 브라우저가_PKCE_웹_암호화를_지원하는가? --아니오--> Implict_Flow
   브라우저가_PKCE_웹_암호화를_지원하는가? --예--> Authorization_Code_with_PKCE
   공개_클라이언트인가? --아니오 --> 클라이언트가_최종_사용자를_가지고_있는가? --예--> 클라이언트가_고도의_신뢰성을_가지고_다른_권한_부여타입은_실행가능하지_않은가? --예--> Resouce_Owner_Flow
   클라이언트가_고도의_신뢰성을_가지고_다른_권한_부여타입은_실행가능하지_않은가? --아니오--> Authorization_Code_Flow
   클라이언트가_최종_사용자를_가지고_있는가? --아니오-->Client_Credentials_Flow
```

* 매개 변수 용어
1. client_id
   * 인가서버에 등록된 클라이언트에 대해 생성된 고유 키
2. client_secret
   * 인가서버에 등록된 특정 클라이언틔의 client_id에 대해 생성된 비밀 값
3. response_type
   * 애플리케이션이 권한 부여 코드 흐름을 시작하고 있음을 인증 서버에 알려준다.
   * code, token, id_token이 있으며 token, id_token은 implicit 권한부여유형에서 지원해야 한다.
   * 서버가 쿼리 문자열에 인증 코드(code), 토큰(token, id_token) 등 반환
4. grant_type
   * 권한 부여 타입 지정 - authorization_code, password, client_credentials, refresh_token
5. redirect_uri
   * 사용자가 응용 프로그램을 성공적으로 승인하면 권한 부여 서버가 사용자를 다시 응용 프로그램으로 리다이렉션 한다.
   * redirect_uri가 초기 권한 부여 요청에 포함된 경우 서비스는 토큰 요청에서도 이를 요구해야 한다.
   * 토큰 요청의 redirect_uri는 인증 코드를 생성할 때 사용된 redirect_uri와 정확히 일치해야 한다. 그렇지 않으면 서비스는 요청을 거부해야 한다.
6. scope
   * 애플리케이션이 사용자 데이터에 접근하는 것을 제한하기 위해 사용된다 
   * 사용자에 의해 특정 스코프로 제한된 권한 인가권을 발행함으로써 데이터 접근을 제한한다.
7. state
   * 응용 프로그램은 임의의 문자열을 생성하고 요청에 포함하고 사용자가 앱을 승인한 후 서버로부터 동일한 값이 반환되는지 확인해야 한다.
   * 이것은 CSRF 공격을 방지하는데 사용된다.

## Authorization Code Grant - 권한 부여 코드 승인 방식
### 개요
1. 흐름 및 특징
    1) 사용자가 애플리케이션을 승인하면 인가서버는 Redirect URI로 임시 코드를 담아서 애플리케이션으로 다시 리다이렉션 한다.
    2) 애플리케이션은 해당 코드를 인가 서버로 전달하고 액세스 토큰으로 교환한다.
    3) 애플리케이션이 액세스 토큰을 요청할 대 해당 요청을 클라이언트 암호로 인증할 수 있으므로 공격자가 인증 코드를 가로채서 스스로 사용할 위험이 줄어 든다.
    4) 액세스 토큰이 사용자 또는 브라우저에 표시되지 않고 애플리케이션에 다시 전달하는 가장 안전한 방법이므로 토큰이 다른 사람에게 누출될 위험이 줄어듬

2. 권한부여 요청 시 매개변수
    * response_type=code(필수)
    * client_id(필수)
    * redirect_uri(선택사항)
    * scope(선택사항)
    * state(선택사항)

3. 액세스 토큰 쿄환 요청 시 매개변수
    * grant_type=authorization_code(필수)
    * code(필수)
    * redirect_uri(필수: 리다이렉션 uri 초기 승인 요청에 포함된 경우)
    * client_id(필수)
    * client_secret(필수)

### 흐름
1. authorization code 요청: 인가서버에게 code를 요청한다.
2. 사용자 인증 & 동의하기: 사용자의 승인 및 동의하에 인가서버가 클라이언트에게 코드를 발급
3. Redirect 및 Access Token 교환 요청: 클라이언트의 권한부여가 승인되고 그 결과로 토큰을 획득

```mermaid
sequenceDiagram
    ResourceOwner ->> Client: 1. 서비스 접속
    Client ->> AuthorizationServer: 2. authorization code(권한부여 코드)요청
    AuthorizationServer ->> ResourceOwner: 3. 로그인 요청
    ResourceOwner ->> AuthorizationServer: 4. 로그인 
    AuthorizationServer ->> ResourceOwner: 5. Consent(동의) 요청
    ResourceOwner ->> AuthorizationServer: 6. 동의
    AuthorizationServer ->> Client: 7. authorization code(권한부여 코드) 응답 리다이렉트
    Client ->> AuthorizationServer: 8. AccessToken 교환 요청
    AuthorizationServer ->> Client: 9. AccessToken + RefreshToken 응답
    Client ->> ResourceServer: 10. AccessToken으로 API 호출
    ResourceServer ->> AuthorizationServer: 11. AccessToken 검증
    AuthorizationServer ->> ResourceServer: 12. AccessToken 검증완료
    ResourceServer ->> Client: 13. 요청한 데이터 응답
```

## Implicit Grant
### 개요
1. 흐름 및 특징
   * 클라이언트 javascript 및 Html 소스 코드를 다운로드한 후 브라우저는 서비스에 직접 API 요청을 한다.
   * 코드 교환 단계를 건너뛰고 대신 액세스 토큰이 쿼리 문자열 조각으로 클라이언트에 즉시 반환된다.
   * 이 유형은 back channel이 없으므로 refresh token을 사용하지 못한다.
   * 토큰 말료시 애플리케이션이 새로운 access token을 얻으려면 다시 OAuth 승인 과정을 거쳐야 한다.

2. 권한 부여 승인 요청시 매개변수
   * grant_type=token(필수), id_token
   * client_id(필수)
   * redirect_uri(필수: 리다이렉션 uri 초기 승인 요청에 포함된 경우)
   * scope(선택사항)
   * state(선택사항)

### 흐름
1. Access Token 요청

```mermaid
sequenceDiagram
    ResourceOwner ->> Client: 1. 서비스 접속
    Client ->> AuthorizationServer: 2. AccessToken 요청
    AuthorizationServer ->> ResourceOwner: 3. 로그인 요청
    ResourceOwner ->> AuthorizationServer: 4. 로그인 
    AuthorizationServer ->> ResourceOwner: 5. Consent(동의) 요청
    ResourceOwner ->> AuthorizationServer: 6. 동의
    AuthorizationServer ->> Client: 7. AccessToken 응답
    Client ->> AuthorizationServer: 8. AccessToken 검증
    AuthorizationServer ->> Client: 9. AccessToken 검증완료
    Client ->> ResourceServer: 10. AccessToken으로 API 호출
    ResourceServer ->> Client: 11. 요청한 데이터 응답
```

## Resource Owner Password Credentials Grant
### 개요
1. 흐름 및 특징
   * 애플리케이션이 사용자 이름과 암호를 액세스 토큰으로 교환할 때 사용된다.
   * 타사 애플리케이션이 이 권한을 사용하도록 허용해서는 안되고 고도의 신뢰할 자사 애플리케이션에서만 사용해야 한다.
   
2. 권한 부여 승인 요청 시 매개변수
   * grant_type=password(필수)
   * username(필수)
   * password(필수)
   * client_id(필수)
   * client_secret(필수)
   * scope(선택사항)

### 흐름
1. Access Token 요청
```mermaid
sequenceDiagram
    ResourceOwner ->> Client: 1. 서비스 접속
    Client ->> AuthorizationServer: 2. 인증정보(username, password)를 포함해 AccessToken 요청
    AuthorizationServer ->> Client: 3. AccessToken 응답
    Client ->> ResourceServer: 4. AccessToken으로 API 호출
    ResourceServer ->> AuthorizationServer: 5. AccessToken 검증
    AuthorizationServer ->> ResourceServer: 6. AccessToken 검증완료
    ResourceServer ->> Client: 7. 요청한 데이터 응답
```

## Client Credentials Grant Type
### 개요
1. 흐름 및 특징
   * 애플리케이션이 리소스 소유자인 동시에 클라이언트의 역할을 한다.
   * 리소스 소유자에게 권한 위임을 받아 리소스에 접근하는 것이 아니라 자기 자신이 애플리케이션을 사용할 목적으로 사용하는 것
   * 서버 대 서버간의 통신에서 사용할 수 있으며 IOT와 같은 장비 애플리케이션과 통신을 위한 인증으로도 사용할 수 있다.
   * Client Id와 Client Secret을 통해 액세스 토큰을 바로 발급받을 수 있다.
   * Client 정보를 기반으로 하기 때문에 사용자 정보를 제공하지 않는다.
   
2. 권한 부여 승인 요청 시 매개변수
    * grant_type=client_credentials(필수)
    * client_id(필수)
    * client_secret(필수)
    * scope(선택사항)

```mermaid
sequenceDiagram
    Client ->> AuthorizationServer: 1. AccessToken 요청
    AuthorizationServer ->> Client: 2. AccessToken 응답
    Client ->> ResourceServer: 3. AccessToken으로 API 호출
    ResourceServer ->> AuthorizationServer: 4. AccessToken 검증
    AuthorizationServer ->> ResourceServer: 5. AccessToken 검증완료
    ResourceServer ->> Client: 6. 요청한 데이터 응답
```

## Refresh Token Grant
### 개요
1. 흐름 및 특직
   * 액세스 토큰이 발급될 때 함께 제공되는 토큰으로 액세스 토큰이 만료되더라도 함께 발급받았던 리프레시 토큰이 유효하다면 인증 과정을 처음부터 반복하지 않고 액세스 토큰을 재발급 받을 수 있다.
   * 한 번 사용된 리프레시 토큰은 폐기되거나 재사용할 수 있다.

2. 권한 부여 승인 요청 시 매개변수
   * grant_type=refresh_token(필수)
   * refresh_token
   * client_id(필수)
   * client_secret(필수)

```mermaid
sequenceDiagram
    Client ->> ResourceServer: 1. AccessToken으로 API 호출
    ResourceServer ->> Client: 2. AccessToken 만료
    Client ->> AuthorizationServer: 3. RefreshToken으로 AccessToken 갱신 요청
    AuthorizationServer ->> Client: 4. AccessToken 갱신
    Client ->> ResourceServer: 5. AccessToken으로 API 호출
    ResourceServer ->> AuthorizationServer: 6. AccessToken 검증
    AuthorizationServer ->> ResourceServer: 7. AccessToken 검증완료
    ResourceServer ->> Client: 8. 요청한 데이터 응답
    
```

## PKCE-enhanced Authorization Code Grant Type
### PKCE(Proof Key for Code Exchange, RFC-6749) 개요
* 코드 교환을 위한 증명 키로서 CSRF 및 권한부여코드 삽입 공격을 방지하기 위한 Authorization Code Grant Flow의 확장버전이다.
* 권한부여코드 요청시 Code Verifier와 Code Challenge를 추가하여 만약 Authorization Code Grant Flow에서 Authorization Code가 탈취 당했을 때 AccessToken을 발급하지 못하도록 차단한다.
* PKCE는 모바일 앱에서 Authorization Code Grant Flow를 보호하도록 설계되었으며, 나중에 SPA에서도 사용하도록 권장되었으며 모든 OAuth2 클라이언트에서 유용하다.

### 코드 생성
1. Code Verifier
   1) 권한부여코드 요청 전에 애플리케이션이 원래 생성한 PKCE 요청에 대한 코드 검증기
   2) 48~128글자수를 가진 무작위 문자열
   3) A-Z, a-z, 0-9, -._~의 ASCII 문자들로만 구성됨
2. Code Challenge
   1) 선택한 Hash 알고리즘으로 Code Verifier를 Hashing 한 후 Base64 인코딩을 한 값
   2) ex) Base64Encode(Sha256(ASCII(Code Verifier)))
3. Code Challenge Method
   1) plain - Code Verifier가 특정 알고리즘을 사용하지 않도록 설정
   2) S256 - Code Verifier가 해시 알고리즘을 사용하도록 설정

### 처리 흐름
1. 단계
   1) 클라이언트는 code_verifier를 생성하고, code_challenge_method를 사용하요 code_challenge를 계산한다.
   2) 클라이언트가 /authorize에 대한 요청을 작성한다.
   3) 권한 서버가 /authorize에 대한 표준 OAutho2 요청 유효성 검증을 수행한다.
   4) 권한 서버가 code_challenge 및 code_challenge_method의 존재를 확인한다.
   5) 권한 서버가 권한 코드에 대해 code_challenge 및 code_challenge_method를 저장한다.
   6) 권한 서버가 권한 코드를 응답한다.
2. 단계
   7) 클라이언트가 code_verifier를 포함해 권한 코드를 /token에 제공한다.
   8) 권한 서버가 /token에 대한 표준 OAuth2 요청 유효성 검증을 수행한다.
   9) 권한 서버가 제공된 code_verifier 및 저장된 code_challenge_method를 사용하요 고유 code_challenge를 생성한다.
   10) 권한 서버가 생성된 code_challenge를 /authorize에 대한 초기 요청에 제공된 값과 비교한다.
   11) 두 값이 일치하면 액세스 토큰이 발행되고 일치하지 않으면 요청이 거부된다.

### code_challenge_method 검증
1. 권한 부요 코드 흐름에 있어 인가서버는 code_verifier를 검증하기 위해 code_challenge_method를 이미 알고 있어야 한다.
2. 토큰 교환시 code_challenge_method가 plain이면 인가서버는 전달된 code_verifier와 보관하고 있는 code_challenge 문자열과 단순히 일치하는지만 확인하면 된다.
3. code_challenge_method가 S256이면 인가서버는 전달된 code_verifier를 가져와 동일한 S256 메소드를 사용하여 변환한 다음 보관된 code_challenge 문자열과 비교해 일치 여부를 판단한다.

# OAuth 2.0 Open ID Connect
## 개요 및 특징
* OpenID Connect 1.0은 OAuth 2.0 프로토콜 위에 구축된 ID 계층으로 OAuth 2.0을 확장하여 인증 방식을 표준화한 OAuth 2.0 기반의 인증 프로토콜이다.
* scope 지정시 'openid'를 포함하면 OpenID Connect 사용이 가능하며 인증에 대한 정보는 ID 토큰(ID Token)이라고 하는 JWT 토큰으로 반환된다.
* OpenID Connect는 클라이언트가 사용자 ID를 확인할 수 있게 하는 보안 토큰인 ID Token을 제공한다.

## ID Token & Scope
### ID Token
* ID 토큰은 사용자가 인증 되었음을 증명하는 결과물로서 OIDC 요청시 access token과 함께 클라이언트에게 전달되는 토큰이다.
* ID 토큰은 JWT로 표현되며 헤더 페이로드 및 서명으로 구성된다.
* ID 토큰은 개인키로 발급자가 서명하는 것으로서 토큰의 출처를 보장하고 변조되지 않았음을 보장한다.
* 애플리케이션은 공개키로 ID 토큰을 검증 및 유효성을 검사하고 만료여부 등 토큰의 클레임을 확인한다.
* 클라이언트는 클레임 정보에 포함되어 있는 사용자명, 이메일을 활용하여 인증 관리를 할 수 있다.

### ID Token VS Access Token
* ID Token은 API 요청에 사용해서는 안되며 사용자의 신원을 확인하기 위해 사용되어져야 한다.
* Access Token은 인증을 위해 사용해서는 안되며 리소스에 접근하기 위해 사용되어져야 한다.

### OIDC Scope
* openid(필수) 클라이언트가 OpenID Connect 요청을 하고 있음을 인증 서버에 알린다.

request: 
```
GET http://[base-server-url]/oauth2/auth?
client_id=myClientApp
&response_type=id_token
&rediecturi=http://localhost:8080
&scope=openid profile email
*state=12345
&nonce=678910
```

### OIDC 로그인 요청
* OIDC 상호 작용 행위자
  1) OpenID Provider: 줄여서 OP라고하며 OpenID제공자로서 최종 사용자를 인증하고 인증 결과와 사용자에 대한 정보를 신뢰 당사자에게 제공할 수 있는 OAuth 2.0 서버를 의미한다.
  2) Relying Party: 줄여서 RP라고 하며 신뢰 당사자로서 인증 요청을 처리하기 위해 OP에 의존하는 OAuth 2.0 애플리케이션을 의미한다.
* 흐름
  1. RP는 OP에 권한 부여 요청을 보낸다.
  2. OP는 최종 사용자를 인증하고 권한을 얻는다.
  3. OP는 ID 토큰과 액세스 토큰을 응답한다.
  4. RP는 Access Token을 사용하여  userInfo 엔드포인트에 요청을 보낼 수 있다.
  5. userInfo 엔드포인트는 최종 사용자에 대한 클레임을 반환한다.

### OIDC 로그인 요청
* 매개변수 요청 및 응답
  * 요청시 openid 범위를 scope 매개변수에 포함해야 한다.
  * response_type 매개변수는 id_token을 포함한다.(response_type이 해당 토큰을 지원해야한다.)
  * 요청은 nonce 매개변수를 포함해야 한다.(Implicit Flow인 경우 필수)
    * 요청에 포함되는 값은 결과 id_token 값에 클레임으로 표함되며 이것은 토큰의 재생 공격을 방지하고 요청의 출처를 식별하는 데 사용할 수 있는 고유 문자열이다.
    * 해당 nonce 클레임에는 요청에 전송된 것과 정확히 동일한 값이 포함되어야 한다. 그렇지 않은 경우 애플리케이션에서 인증을 거부해야 한다.

# OAuth 2.0 Client
## 스프링 시큐리티와 OAuth 2.0

### Spring Security Oauth Project (Deprecated)
```
Client Support + Resource Server + Authorization Server
```
### Spring Security 5
```
Client Support + Resource Server 
```
Authorization Server를 별도로 

## OAuth 2.0 Client 소개
### 개요
* OAuth 2.0 인가 프레임워크의 역할 중 인가서버 및 리소스 서버와의 통신을 담당하는 클라이언트의 기능을 필터 기반으로 구현한 모듈
* 간단한 설정만으로 OAuth 2.0 인증 및 리소스 접근 권한, 인가서버 엔드포인트 통신등의 구현이 가능하며 커스터마이징, 확장이 용이하다.

* OAuth 2.0 Login
  * 애플리케이션의 사용자를 외부 OAuth 2.0 Provider나 OpenID Connect 1.0 Provider 계정으로 로그인할 수 있는 기능을 제공한다.
  * 클로벌 서비스 프로바이더인 구글, 깃허브 등 로그인을 OAuth 2.0 로그인을 구현할 수 있도록 지원한다.
  * OAuth 2.0 인가 프레임워크의 권한 부여 유형중 Authorization Code 방식을 사용한다.
* OAuth 2.0 Client
  * OAuth 2.0 인가 프레임워크에 정의된 클라이언트 역할을 지원한다.
  * 인가 서버의 권한 부여 유형에 따른 엔드포인트와 직접 통신할 수 있는 API를 제공한다.
    * Client Credentials
    * Resource Owner Password Credentials
    * Refresh Token
  * 리소스 서버의 보호자원 접근에 대한 연동 모듈을 구현할 수 있다.

# OAuth 2.0 Client Fundamentals
## application.yml / OAuth2ClientProperties
### 클라이언트 권한 부여 요청 시작
1. 클라이언트가 인가서버로 권한 부여 요청을 하거나 토큰 요청을 할 경우 클라이언트 정보 및 엔드포인트 정보를 참조해서 전달한다.
2. application.yml 환경설정 파일에 클라이언트 설정과 인가서버 엔드포인트 설정을 한다.
3. 초기화가 진행되면 application.yml에 있는 클라이언트 및 엔드포인트 정보가 OAuth2ClientProperties의 각 속성에 바인딩 된다.
4. OAuth2ClientProperties에 바인딩 되어있는 속성의 값은 인가서버로 권한부여 요청을 하귀 위한 Client Registration 클래스의 필드에 저장된다.
5. OAuth2Client는 ClientRegistration를 참조해서 권한부여 요청을 위한 매개변수를 구성하고 인가서버와 통신한다.

### application.yml
```yml
spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            authorization-grant-type: authorization_code  # OAuth2.0 권한 부여 타입
            client-id: oauth2-client-app  # 서비스 공급자에 등록된 클라이언트 아이디
            client-name: oauth2-client-app # 클라이언트 이름
            client-secret: KkIpKeQmJEj6wGXIhCZ0b95wY1Z0oHD1 # 서비스 공급자에 등록된 클라이언트 비밀번호
            redirect-uri: http://localhost:8081/login/oauth2/codekeycloak # 인가서버에서 권한 코드 부여후 클라이언트로 리다이렉트 하는 위치
            client-authentication-method: client_secret_post  # 클라이언트 자격증명 전송방식
            scope: openid,email # 리소스 접근 제한 범위
        provider:
          keycloak:
            authorization-uri: http://localhost:8080/realms/oauth2/protocol/openid-connect/auth # OAuth2.0 권한 코드 부여 엔드포인트
            issuer-uri: http://localhost:8080/realms/oauth2 # 서비스 공급자 위치
            jwk-set-uri: http://localhost:8080/realms/oauth2/protocol/openid-connect/certs # OAuth2.0 JwKSetUri 엔드포인트
            token-uri: http://localhost:8080/realms/oauth2/protocol/openid-connect/token # OAuth2.0 토큰 엔드포인트
            user-info-uri: http://localhost:8080/realms/oauth2/protocol/openid-connect/userinfo # OAuth2.0 userInfo 엔드포인트
            user-name-attribute: preferred_username # OAuth2.0 사용자명을 추출하는 클레임명
```

### OAuth2ClientProperties(prefix ="spring.security.oauth2.client")
* Registration은 인가 서버에 등록된 클라이언트 및 요청 파라미터 정보를 나타낸다.
* Provider는 공급자에서 제공하는 엔드포인트 등의 정보를 나타낸다.
* 클라이언트 및 공급자의 정보를 registration /provider 맵에 저장하고 인가서버와의 통신 시 각 항목을 참조하여 사용한다.

## ClientRegistration
### 개념
* OAuth 2.0 또는 OpenID connect 1.0 Provider에서 클라이언트의 등록 정보를 나타낸다.
* ClientRegistration은 OpenID Connect Provider의 설정 엔드포인트나 인가 서버의 메타데이터 엔드포인트를 찾아 초기화할 수 있다.
* ClientRegistration의 메소드를 사용하면 편리하게 ClientRegistration을 설정할 수 있다.
  * `ClientRegistration clientRegistration = ClientRegistration.fromIssuerLocation("https://idp.example.com/issuer").build();`

#### ClientRegistration
* registrationId: clientRegistration을 식별할 수 있는 유니크한 ID
* clientId: 클라이언트 식별자
* clientSecret: 클라이언트 secret
* clientAuthenticationMethod: provider에서 클라이언트를 인증할 때 사용할 메소드로서 basic, port, none(public 클라이언트)을 지원한다.
  * authorizationGrantType: OAuth 2.0 인가 프레임워크는 네가지 권한을 부여 타입을 정의하고 있으며 지원하는 값은 `authorization_code`, `implicit`, `client_credentials`, `password`다.
* redirectUriTemplate: 클라이언트에 등록한 리아딩렉트 URL로, 사용자의 인증으로 클라이언트에 접근 권한을 부여하고 나면, 인가 서버가 이 URL로 최종 사용자의 브라우저를 리다이렉트 시킨다.
* scopes: 인가 요청 플로우에서 클라이언트가 요청한 openid, 이메일, 프로필 등의 scope
* clientName: 클라이언트를 나타내는 이름으로 자동 생성되는 로그인 페이지에서 노출하는 등에 사용한다.
* tokenUri: 인가 서버의 토큰 엔드포인트 URL
* jwkSetUri: 인가 서버에서 Json Web Key Set을 가져올 때 사용할 URI. 이 keySet에는 ID 토큰의 Json Web Signature를 검증할 때 사용할 암호키가 있으며, UserInfo 응답을 검증할 때 사용할 수 있다.
* configurationMetadata: OpenID Provider 설정 정보로서 application.properties에 spring.securityoauth2.client.provider를 설정했을 때만 사용할 수 있다.
* uri: 인증된 최종 사용자의 클레임/속성에 접근할 때 사용하는 uri
* authenticationMethod: 엔드포인트로 액세스 토큰을 전송할 때 사용할 인증 메소드. header, form, query를 지원한다.
* userNameAttributeName: userInfo 응답에 있는 속성 이름으로, 최종 사용자의 이름이나 식별자에 접근할 때 사용한다.

### CommonOAuth2Provider
* OAuth 2.0 공급자 정보를 제공하는 클래스로서 글로벌 서비스 제공자 일부는 기본으로 제공되어진다.
* Client ID와 Client Secret은 별도로 application.properties에 작성해야 한다.
* 국내 공급자 정보는 수동으로 작성해서 사용해야 한다.
* 클라이언트 기준인 Registration 항목과 서비스 제공자 기준인 Provider 항목으로 구분하여 설정한다.
* application.properties가 아닌 Java Config 방식으로 ClientRegistration 등록을 설정할 수 있다.
* clientRegistration 객체를 생성할 수 있는 빌더 클래스를 반환한다.

## ClientRegistrationRepository 이해 및 활용
### 개념
* ClientRegistrationRepository는 OAuth 2.0 & OpenId Connect 1.0의 ClientRegistration 저장소 역할을 한다.
* 클라이언트 등록 정보는 궁극적으로 인가 서버가 저장하고 관리하는데 이 레포지토리는 인가 서버에 일차적으로 저장된 클라이언트 등록 정보의 일부 검색하는 기능을 제공한다.
* 스프링 부트 2.x 자동 설정은 spring.security.oauth2.client.registration.[registrationId] 하위 프로퍼티를 ClientRegistration 인스턴스에 바인딩하며, 각 ClientRegistration 객체를 ClientRegistrationRepository의 안에 구성한다.
* ClientRegistrationRepository의 디폴트 구현체는 InMemoryClientRegistrationRepositoryek.
* 자동 설정을 사용하면 ClientRegistrationRepository도 ApplicationContext 내 @Bean으로 등록하므로 필요하다면 원하는 곳에 의존성을 주입할 수 있다.

## 자동설정에 의한 초기화 과정 이해
1. OAuth2ImportSelector
2. OAuth2ClientConfiguration
3. OAuth2ClientWebMvcImportSelector
4. OAuth2ClientWebMvcSecurityConfiguration
   * DefaultOAuth2AuthorizedClientManager
   * HandlerMethodArgumentResolver

1. OAuth2ClientAutoConfiguration
   * OAuth2ClientRegistrationRepositoryConfiguration
     * InMemoryClientRegistrationRepository
   * OAuth2ClientWebSecurityConfiguration
     * ImMemoryOAuth2AuthorizedClientService
     * AuthenticatedPrincipalOAuth2AuthorizedClientRepository
     * oauth2SecurityFilterChain

# OAuth 2.0 Client - oauth2Login()
## OAuth2LoginConfigurer 초기화 이해
* init
  * OAuth2LoginAuthenticationFilter
  * OAuth2LoginAuthenticationProvider
  * OidcAuthorizationCodeAuthenticationProvider
  * DefaultLoginPageGeneratingFilter

1. configure
2. OAuth2AuthorizationRequestRedirectFilter

## OAuth2 로그인 구현 - OAuth 2.0 Login Page 생성
* OAuth 2.0 로그인 페이지 자동 생성
  * 기본적으로 OAuth 2.0 로그인 페이지 DefaultLoginPageGeneratingFilter가 자동으로 생성해 준다.
  * 이 디폴트 로그인 페이지는 OAuth 2.0 클라이언트 명을 보여준다.
  * 링크를 누르면 인가 요청을 시작할 수 있다.
* 요청 매핑 Url
  * RequestMatcher : /oauth2/authorization/{registrationId}*
  * 디폴트 로그인 페이지를 재정의하려면 `oauth2Login().loginPage()`를 사요하면 된다.

## OAuth2 로그인 구현 - Authorization Code 요청하기
### 개요
* 주요 클래스
  * OAuth2AuthorizationRequestRedirectFilter
    * 클라이언트는 사용자의 브라우저를 통해 인가 서버의 권한 부여 엔드포인트로 리다이렉션하여 권한 코드 부여 흐름을 시작한다.
    * 요청 매핑 url
      * AuthorizationRequestMatcher: /oauth2/authorization/{registrationId}*
      * AuthorizationEndpointConfig. authorizationRequestBaseUri를 통해 재정의될 수 있다.
  * DefaultOAuth2AuthorizationRequestResolver
    * 웹 요청에 대하여 OAuth2AuthorizationRequest 객체를 최종 완성한다.
    * /oauth2/authorization/{registrationId}와 일치하는지 확인해서 일치하면 registrationId를 추출하고 이를 사용해 ClientRegistration을 가져와 OAUth2AuthorizationRequest를 빌드한다.
  * OAuth2AuthorizationRequest
    * 토큰 엔드포인트 요청 파라미터를 담은 객체로서 인가 응답을 연계하고 검증할 때 사용한다.
  * OAuth2AuthorizationRequestRepository
    * 인가 요청을 시작한 시점부터 인가 요청을 받는 시점까지 OAuth2AuthorizationRequest를 유지해준다.

## OAuth2 로그인 구현 - Access Token 교환하기
### 개요
* 주요 클래스
  * OAuth2LoginAuthenticationFilter
    * 인가서버로부터 리다이렉트 되면서 전달된 code를 인가 서버의 Access Token으로 교환하고 Access Token이 저장된 OAuth2LoginAuthenticationToken을 AuthenticationManager에 위임하여 UserInfo 정보를 요청해서 최종 사용자에 로그인 한다.
    * OAuth2AuthorizedClientRepository를 사용하여 OAuth2AuthorizedClient를 저장한다.
    * 인증에 성공하면 OAuth2AuthorizedClientRepository를 사용하여 OAuthorizedClient를 저장한다.
    * 인증에 성공하면 OAuth2AuthenticationToken이 생성되고 SecurityContext에 저장되어 인증처리를 완료한다.
    * 요청 매핑 url
      * RequestMatcher: /login/oauth2/code/*
  * OAuth2LoginAuthenticationProvider
    * 인가 서버로부터 리다이렉트 된 이후 프로세스를 처리하며 Access Token으로 교환하고 이 토큰을 사용하여 UserInfo 처리를 담당한다.
    * scope에 openid가 포함되어있으면 OidcAuthorizationCodeAuthenticationProvider를 호출하고 아니면 OAuth2AuthorizationCodeAuthenticationProvider를 호출하도록 제어한다.
  * OAuth2AuthorizationCodeAuthenticationProvider
    * 권한 코드 부여 흐름을 처리하는 AuthenticationProvider
    * 인가 서버에 Authorization Code와 Access Token의 교환을 담당하는 클래스
  * OidcAuthorizationCodeAuthenticationProvider
    * OpenID Connect core 1.0 권한 코드 부여 흐름을 처리하는 AuthenticationProvider이며 요청 scope에 openid가 존재할 경우 실행된다.
  * DefaultAuthorizationCodeTokenResponseClient
    * 인가 서버의 token 엔드포인트로 통신을 담당하며 Access Token을 받은후 OAuth2AccessTokenResponse에 저장하고 반환한다.

## OAuth2 로그인 구현 - OAuth 2.0 User 모델 소개
### 개요
* OAuth2UserService
  * 액세스 토큰을 사용해 UserInfo 엔드포인트 요청으로, 최종 사용자의 속성을 가져오며 OAuth2User 타입의 객체를 리턴한다.
  * 구현체로 DefaultOAuth2UserService와 OidcUserService가 제공된다.
  
* DefaultOAuth2UserService
  * 표준 OAuth 2.0 Provider를 지원하는 OAuth2UserService 구현체다.
  * OAuth2UserRequest에 AccessToken을 담아 인가서버와 통신 후 사용자의 속성을 가지고 온다.
  * 최종 OAuth2User 타입의 객체를 반환한다.
* OidcUserService
  * OpenID Connect 1.0 Provider를 지원하는 OAuth2UserService 구현체다
  * OidcUserRequest에 있는 ID Token을 통해 인증 처리를 하며 필요시 DefaultOAuth2UserService를 사용해 UserInfo 엔드포인트의 사용자 속성을 요청한다.
  * 최종 OidcUser 타입의 객체를 반환한다.

```mermaid
sequenceDiagram
    OAuth 2.0 Client ->> Authorization Server: /token
    Authorization Server ->> OAuth 2.0 Client: access_token
    OAuth 2.0 Client ->> DefaultOAuth2UserService: 인가서버로 사용자 정보 조회
    DefaultOAuth2UserService ->> Authorization Server: userAttributes
```
```mermaid
sequenceDiagram
    OAuth 2.0 Client ->> Authorization Server: /token?scope=openid
    Authorization Server ->> OpenID Connect: OpenID Connect protocol
    OpenID Connect ->> Authorization Server: id_token
    Authorization Server ->> OAuth 2.0 Client: id_token, access_token
    OAuth 2.0 Client ->> OidcUserService: id_token을 가지고 있어서 인가서버와 통신하지 않고 인증처리
    OidcUserService ->> OAuth 2.0 Client: OidcUser
```
```mermaid
sequenceDiagram
    OidcUserService ->> DefaultOAuth2UserService: ""
    DefaultOAuth2UserService ->> Authorization Server: /userInfo?access_token=${token}
    Authorization Server ->> DefaultOAuth2UserService: userAttributes
    DefaultOAuth2UserService ->> OidcUserService: OidcUserInfo
    OidcUserService ->> OAuth 2.0 Client: OidcUser
```

## 구조
* DefaultOAuth2UserService는 OAuth2User 타입의 객체를 반환한다.
* OidcUserService는 OidcUser 타입의 객체를 반환한다.
* OidcUserRequest의 승인된 토큰에 포함되어 있는 scope 값이 accessibleScopes의 값 들중 하나 이상 포함되어 있을 경우 UserInfo 엔드 포인트를 요청한다.

## OAuth2User & OidcUser
### 개요
* 시큐리티는 UserAttributes 및 ID Token Claims을 집계 & 구성하여 OAuth2와 OidcUser 타입의 클래스를 제공한다.
* OAuth2User
  * OAuth 2.0 Provider에 연결된 사용자 주체를 나타낸다.
  * 최종 사용자의 인증에 대한 정보인 Attributes를 포함하고 있으며 first name, middle name, last name, email, phone number, address 등으로 구성된다.
  * 기본 구현체는 DefaultOAuth2User이며 인증 이후 Authentication의 principal 속성에 저장된다.
* OidcUser
  * OAuth2User를 상송한 인터페이스이며 OIDC Provider에 연결된 사용자 주체를 나타낸다.
  * 최종 사용자의 인증에 대한 정보인 Claims를 포함하고 있으며 OidcIdToken 및 OidcUserInfo에서 집계 및 구성된다.
  * 기본 구현체는 DefaultOidcUser이며 DefaultOAuth2User를 상송하고 있으며 인증 이후 Authentication의 principal 속성에 저장된다.

```mermaid
sequenceDiagram
    OAuth 2.0 Client ->> Authorization Server: /userInfo?access_token
    Authorization Server ->> OAuth 2.0 Client: OAuth2User
```
```mermaid
sequenceDiagram
    OAuth 2.0 Client ->> Authorization Server: /token?scope=openid
    Authorization Server ->> OpenID Connect: claims, id_token 요청
    OpenID Connect ->> OAuth 2.0 Client: claims, id_token
```

## OAuth2 로그인 구현 - UserInfo 엔드포인트 요청하기
* OAuth 2.0 Provider UserInfo 엔드포인트 요청하기
### 개요
* 주요 클래스 
  * DefaultOAuth2UserService
    * `public OAuth2User loadUser(OAuth2UserReqeust userRequest)
  * OAuth2UserRequestEntityConverter`
    * OAuth2UserReqeust를 ResponseEntity로 컨버터 한다.
  * RestOperations

* OpenID Connect Provider OidcUserInfo 엔드포인트
* 주요 클래스
  * OidcUserService
    * `public OidcUser loadUser(OidcUserRequest userReqeust)`
    * 내부에 DefaultOAuth2UserService를 가지고 있으며 OIDC 사양에 부합할 경우 OidcUserReqeust를 넘겨주어 인가서버와 통신한다.
    * OidcUser 타입의 객체를 반환한다.

## OAuth2 로그인 구현 - OpenID Connect 로그아웃
* 개념
  * 클라이언트는 로그아웃 엔드포인트를 사용하여 웹 브라우저에 대한 세션과 쿠키를 지운다.
  * 클라이언트 로그아웃 성공 후 OidcClientInitiatedLogoutSuccessHandler를 호출하여 OpenID Proivder 세션 로그아웃 요청한다.
  * OpenID Provider 로그아웃 성공하면 지정된 위치로 리다이렉트 한다.
  * 인가 서버 메타데이터 사양에 있는 로그아웃 엔드포인트는 end_session_endpoint로 정의되어있다.
  
* API 설정
```java
http.logout()
    .logoutSuccessHandler(oidcLogoutSuccessHandler())
    .invalidateHttpSession(true)
    .clearAuthentication(true)
    .deleteCookies("JSESSIONID")
```
```java
private OidcClientInitiatedLogoutSuccessHandler oidcLogoutHandler() {
    OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
    successHandler.setPostLogoutRedirectUri("http://localhost:8081/login");
    return successHandler;
}
```

## OAuth2 로그인 구현 - Spring MVC 인증 객체 참조하기
* Authentication
  * `public void dashboard(Authentication authentication) {}`
    * oauth2Login()으로 인증을 받게 되면 Authentication은 OAuth2AuthenticationToken 타입의 객체로 바인딩 된다.
    * principal에는 OAuth2User 타입 혹은 OidcUser 타입의 구현체가 저장된다.
    * DefaultOidcUser는 OpenID Connect 인증을 통해 ID Token 및 클레임 정보가 포함된 객체이다.
* @AuthenticationPrincipal
  * `public void dashboard(@AuthenticationPrincipal Oauth2User principal or OidcUser principal) {}`
  * AuthenticationPrincipalArgumentResolver 클래스에서 요청을 가로채어 바인딩 처리를 한다.
    * Authentication을 SecurityContext로부터 꺼내와서 Principal 속성에 OAuth2User 혹은 OidcUser 타입의 객체를 저장한다.


## API 커스텀 구현 -Authorization BaseUrl & Redirection BaseUrl
```java
http.oauth2Login(oauth2 -> oauth2
        .loginPage("/login")
        .loginProcessingUrl("/login/v1/oauth2/code/")
        .authorizationEndpoint(authorizationEndpointConfig -> authorizationEndpointConfig.baseUri("/oauth2/v1/authorization"))
        .redirectionEndpoint(redirectionEndpointConfig -> redirectionEndpointConfig.baseUri("/login/v1/oauth2/code/*"))
)
```
* authorizationEndpoint.baseUri("/ouaht2/v1/authorization")은 권한 부여 요청 BaseUri를 커스텀한다.
  * 1단계 권한 부여 요청을 처리하는 OAuth2AuthorizationRequestRedirectFilter에서 요청에 대한 매칭 여부를 판단한다.
  * 설정에서 변경한 값이 클라이언트의 링크 정보와 일치하도록 맞추어야 한다.
* redirectionEndpoint.baseUri("/login/v1/oauth2/code/*)는 인가 응답의 baseUri를 커스텀한다.
  * Token 요청을 처리하는 OAuth2LoginAuthenticationFilter에서 요청애 대한 매칭 여부를 판단한다.
    * application.yml 설정 파일에서 registration 속성의 redirectUri 설정에도 변경된 값을 적용해야 한다.
    * 인가 서버의 redirectUri 설정에도 변경된 값을 적용해야 한다.
  * loginProcessUrl("/login/v1/oauth2/code/*)를 설정해도 결과는 동일하지만 redirectionEndpoint.baseUri가 더 우선이다.

## API 커스텀 구현 - OAuth2AuthorizationRequestResolver
### OAuth2AuthorizationRequestResolver
* Authorization Code Grant 방식에서 클라이언트 인가서버로 권한 부여 요청을 할 때 실행되는 클래스
* OAuth2AuthorizationRequestResolver는 OAuth 2.0 인가 프레임워크에 정의된 표준 파라미터 외에 다른 파라미터를 추가하는 식으로 인가 요청을 할 때 사용한다.
* DefaultOAuth2AuthorizationRequsetResolver가 디폴트 구현체로 제공되며 Consumer<OAuth2AuthorizationRequest.Builder> 속성에 커스텀할 내용을 구현한다.

# OAuth 2.0 Client - oauth2Client()
## OAuth2AuthorizedClient
### 개념
* OAuth2AuthorizedClient는 인가받은 클라이언트를 의미하는 클래스다.
* 최종 사용자(리소스 소유자)가 클라이언트에게 리소스에 접근할 수 있는 권한을 부여하면, 클라이언트를 인가된 클라이언트로 간주한다.
* OAuth2AuthorizedClient는 AccessToken과 RefreshToken을 ClientRegistration(클라이언트)와 권한을 부여한 최종 사용자인 Principal과 함께 묶어 준다.
* OAuth2AuthorizedClient의 AccessToken을 사용해 리소스 서버의 자원에 접근 할 수 있으며 인가 서버와의 통신으로 토큰을 검증할 수 있다.
* OAuth2AuthorizedClient의 ClientRegistration과 AccessToken을 사용해서 UserInfo 엔드포인트로 요청할 수 있다.

### OAuth2AuthorizedClientRepository
* OAuth2AuthorizedClientRepository는 다른 웹 요청이 와도 동일한 OAuthorizedClient를 유지하는 역할을 담당한다.
* OAuth2AuthorizedClientService에게 OAuth2AuthorizedClient의 저장, 조회, 삭제 처리를 위임한다.

### OAuth2AuthorizedClientService
* OAuth2AuthorizedClientService는 애플리케이션 레벨에서 OAuth2AuthorizedClient를 관리(저장, 조회, 삭제)한다.

### 웹 애플리케이션에서 활용
* OAuth2AuthorizedClientRepository나 OAuth2AuthorizedClientService는 OAuth2AuthorizedClient에서 OAuth2AccessToken을 찾을 수 있는 기능을 제공하므로 보호중인 리소스 요청을 시작할 때 사용할 수 있다.

## OAuth2AuthorizationCodeGrantFilter
### 개념
* AuthorizationCodeGrant 방식으로 권한 부여 요청을 지원하는 필터
* 인가 서버로부터 리다이렉트 되면 전달된 code를 인가 서버의 AccessToken으로 교환한다.
* OAuth2AuthorizedClientRepository를 사용하여 OAuth2AuthorizedClient를 저장후 클라이언트의 RedirectUri로 이동한다.

### 실행 조건
* 요청 파라미터에 code와 state 값이 존재하는지 확인
* OAuth2AuthorizationRequest 객체가 존재하는 지 확인

## DefaultOAuth2AuthorizedClientManager
### 개념
* OAuth2AuthorizedClinet를 전반적으로 관리하는 인터페이스
* OAuth2AuthorizedClientProvider로 OAuth 2.0 클라이언트에 권한 부여
  * Client Credentials Flow
  * Resource Owner Password Flow
  * Refresh Token Flow
* OAuth2AuthorizedClientService나 OAuth2AuthorizedClientRepository에 OAuth2AuthrizedClient 저장을 위임한 후 OAuth2AuthorizedClient 최종 반환
* 사용자 정의 OAuth2AuthorizationSuccessHandler 및 OAuth2AuthorizationFailureHandler를 구성하여 성공/실패 처리를 변경할 수 있다.
* invalid_grant 오류로 인해 권한 부여 시도가 실패하면 이전에 저장된 OAuth2AuthorizedClient가 OAuth2AuthorizedClientRepository에서 제거 된다.

### 특징
* clientRegistrationRepository: 인가 서버가 저장하고 소유하고 있는 클라이언트 등록 정보의 복사본을 저장한다.
* OAuth2AuthorizedClientRepository: 클라이언트와 인가 서버 요청 간에 OAuth2AuthorizedClient 정보를 계속 유지하며 OAuth2AuthorizedClientService에게 위임하여 처리한다.
* OAuth2AuthorizedClient의 저장, 조회, 삭제 과리를 담당한다.

* OAuth 2.0 클라이언트 인증(또는 재인증) 하기 위한 전략 클래스로 특정 권한 부여 유형을 구현한다.
  * ClientCredentialsOAuth2AuthorizedClientProvider
  * PasswordOAuth2AuthorizedClientProvider
  * RefreshTokenOAuthorizedClientProvider

* 인가 서버의 토큰 엔드포인트에서 액세스 토큰 저장 증명에 대한 인증 코드를 "교환" 하기 위한 전략
  * DefaultClientCredentialsTokenResponseClient
  * DefaultPasswordTokenResponseClient
  * DefaultRefreshTokenResponseClient

### 생성
```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientRepository authorizedClientRepository) {
    OAuth2AuthorizedClientProvider auth2AuthorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .refreshToken()
            .clientCredentials()
            .password()
            .build();

    DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
    authorizedClientManager.setAuthorizedClientProvider(auth2AuthorizedClientProvider);
    return authorizedClientManager;
}
```
## DefaultOAuth2AuthorizedClientManager
### 개요
* 스프링 시큐리티의 OAuth2Login 필터에 의한 자동 인증 처리를 하지 않고 DefaultOAuth2AuthorizedClientManager 클래스를 사용하여 Spring MVC에서 직접 인증 처리를 하는 로그인 기능을 구현한다.
```java
@Bean
public OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientRepository authorizedClientRepository) {
    OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .password()
            .clientCredentials()
            .refreshToken()
            .build();

    DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
    return authorizedClientManager;
}
```

### 기본 구성
* AppConfig - DefaultOAuth2AuthorizedClientManager 빈 생성 및 설정 초기화
* DefaultOAuth2AuthorizedClientManager - OAuth2 권한 부여 흐름을 처리
* LoginController - DefaultOAuth2AuthorizedClientManager를 사용해서 로그인 처리
* home.html - 인증 받은 사용자만 접근 가능
* index.html, client.html - 모든 사용자 접근 가능
* application.yml - 권한 부여 유형을 client_credentials, password, refresh 타입으로 설정한다.

### 로그인 구현 순서
1. DefaultOAuth2AuthorizedClientManager 빈 생성 및 파라미터 초기 값들을 정의한다.
2. 권한 부여 유형에 따라 요청이 이루어지도록 application.yml 설정을 조정한다.
3. /oauth2Login 주소로 권한 부여 흐름을 요청한다.
4. DefaultOAuth2AuthorizedClientManager에게 권한 부여를 요청한다.
5. 권한 부여가 성공하면 OAuth2AuthorizationSuccessHandler를 호출하여 인증 이후 작업을 진행한다.
   1. DefaultOAuth2AuthorizedClientManager의 최종 반환값인 OAuth2AUthorizedClient를 OAuth2AuthorizedClientRepository에 저장한다.
6. OAuth2AUthorizedClient에서 AccessToken을 참조하여 /userinfo 엔드포인트 요청으로 최종 사용자 정보릎 가져온다.
7. 사용자 정보 권한을 가지고 인증객체를 만든 후 SecurityContext에 저장하고 인증을 완료한다.

## @RegisteredOAuth2AuthorizedClient 이해 및 활용
### @RegisteredOAuth2AuthorizedClient
* 파라미터를 OAuth2AuthorizedClient 타입 인자로 리졸브 해준다.
* OAuth2AuthorizedClientArgumentResolver에서 요청을 가로채어 유형별로 권한 부여 흐름을 실행하도록 한다.
* 이 방법은 OAuth2AuthorizedClientManager나 OAuth2AuthorizedClientService로 OAuth2AuthorizedClient에 접근하는 것보다 편하다.

# OAuth 2.0 Client Social Login
## Google 연동
### 연동 절차
1. OAuth2 Client와 Google 인가 서버와의 연동을 통해 인증/인가 프로세스를 구현한다.
2. 구글 서비스에 신규 서비스를 생성한다. https://console.cloud.google.com
3. application.yml 설정
```yml
Spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
            client-secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Naver 연동
### 연동 절차
1. OAuth2 Client와 Naver 인가 서버와의 연동을 통해 인증/인가 프로세스를 구현한다.
2. 구글 서비스에 신규 서비스를 생성한다. https://developers.naver.com/main/
3. application.yml 설정
```yml
Spring:
  security:
    oauth2:
      client:
        registration:
          naver:
            client-id: xxxxxxxxxxxxxxxxxxxxxxxx
            client-secret: xxxxxxxxxxxxxxxxxxxxx
            authorization-grant-type: authorization_code
            client-name: naver-client-app
            redirect-uri: http://localhost:8081/login/oauth2/code/naver
            scope: profile, email
        provider:
          naver:
            authorization-uri: https://nid.naver.com/ouath2.0/authorize
            jwk-set-uri: https://openapi.naver.com/v1/nid/verify
            user-info-uri: https://openapi.naver.com/v1/nid/me
            user-name_attribute: response
            client-id: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
            client-secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

