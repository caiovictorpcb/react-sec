patterns = [
    r'\b[a-zA-Z_$]{1,3}\s*=\s*["\'][A-Za-z0-9_\-]{10,}["\']',
    r'[{,]\s*["\']?[a-zA-Z_$]{1,3}["\']?\s*:\s*["\'][A-Za-z0-9_\-]{10,}["\']',
    # Funções anônimas ou arrow functions suspeitas manipulando strings
    r'\b[a-zA-Z_$]{1,3}\s*=\s*function\s*\([^)]*\)\s*{[^}]*["\'][A-Za-z0-9_\-]{10,}["\']',
    r'\([^)]*\)\s*=>\s*{[^}]*["\'][A-Za-z0-9_\-]{10,}["\']',
    # Strings longas em geral (base64, tokens, etc)
    r'["\'][A-Za-z0-9+/=]{40,1000}["\']',
    # Propriedades de objetos encurtadas: "a.b=" ou "a.b:"
    r'\b[a-zA-Z_$]{1,3}\.[a-zA-Z_$]{1,3}\s*[:=]\s*["\']?[A-Za-z0-9_\-]{10,}["\']?',
    r'(api|secret|access)[-_]?(key|token)\s*[:=]\s*["\']?[A-Za-z0-9-_]{10,}["\']?',
    # Variáveis de ambiente (já existente, mantido)
    r"process\.env\.[A-Z_]+",
    # Uso de eval (já existente, mantido)
    r"eval\s*\(",
    # Injeção em innerHTML (já existente, mantido)
    r"innerHTML\s*=",
    # NOVOS PADRÕES
    # Credenciais hardcoded em strings
    r'(password|pwd|pass)\s*[:=]\s*["\'][^"\']{6,50}["\']',
    # URLs com possíveis credenciais
    r'https?://[^"\']*@(?!.*\.git)[^"\']+',
    # Chaves privadas (ex.: JWT, AWS, etc.)
    r'["\']?[A-Za-z0-9+/=]{20,}\.["\']?[A-Za-z0-9+/=]{20,}\.["\']?[A-Za-z0-9+/=]{20,}',
    # Variáveis suspeitas com "secret" ou "key" no nome
    r'\b[A-Za-z0-9_]*(secret|key|token)[A-Za-z0-9_]*\s*[:=]\s*["\']?[A-Za-z0-9-_]{10,}["\']?',
    # Base64 suspeito (longas strings codificadas)
    r'["\']?[A-Za-z0-9+/=]{40,1000}["\']?',
    # Objetos com propriedades sensíveis
    r'\{\s*["\']?(apiKey|accessToken|secretKey|password)["\']?\s*:\s*["\'][^"\']+["\']',
    # Funções JavaScript perigosas
    r'(setTimeout|setInterval|Function)\s*\(\s*["\'].*?["\']\s*,',
    # Comentários com informações sensíveis
    r"//.*?(key|token|secret|password|pwd)\s*[:=]?.*?[\w-]{10,}",
    # Strings com padrões de UUID (potenciais IDs sensíveis)
    r'["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']?',
    # Configurações de conexão de banco de dados
    r'(mongodb|mysql|postgres|sql)[^\n"]{0,50}:\/\/[^"\']+',
    # Chaves de serviços específicos (ex.: Stripe, Firebase)
    r"(sk_|pk_)[A-Za-z0-9-_]{20,}",
    r'\/(admin|dashboard|panel|manager|backoffice)(\/|["\'\s])',
    # Uso de localStorage e sessionStorage
    r"localStorage\.setItem\s*\(",
    r"localStorage\.getItem\s*\(",
    r"sessionStorage\.setItem\s*\(",
    r"sessionStorage\.getItem\s*\(",
    # Checagens de autenticação/autorização simples
    r"if\s*\(\s*!?(isLoggedIn|authenticated|isAuth|userToken)\s*\)",
    r'if\s*\(\s*!?localStorage\.getItem\s*\(\s*["\'](token|auth|session)["\']\s*\)\s*\)',
    r'headers\s*[:=]\s*{[^}]*["\']Authorization["\']\s*:\s*["\']Bearer\s+[A-Za-z0-9-_\.]+["\']',
    # Indícios de tokens em headers
    r'["\']Authorization["\']\s*:\s*["\']Bearer\s+[A-Za-z0-9-_\.]+["\']',
]
