import re
import google.generativeai as genai
from dotenv import load_dotenv
import os

from patterns import patterns

load_dotenv()

genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))


def find_secrets(js_code):
    findings = []
    for pattern in patterns:
        matches = re.findall(pattern, js_code)
        findings.extend(matches)
    return findings


def get_analyse_code_prompt(js_code):
    return f"""Você é um especialista em segurança de aplicações web. Analise o seguinte código JavaScript/React e gere um relatório objetivo e direto, seguindo exatamente os tópicos abaixo. Utilize bullet points para listar os achados. Para cada item, diga o que foi encontrado (se algo for encontrado) e onde, ou diga “Nada encontrado” caso não haja nada suspeito.

        1. Chaves e segredos expostos

        Verifique se há tokens, chaves de API, segredos ou credenciais hardcoded.

        2. Rotas sensíveis no frontend

        Identifique rotas de admin, dashboards, páginas protegidas visíveis no código cliente.

        3. Chamadas de API e endpoints

        Liste todas as chamadas de API. Aponte se há chamadas para endpoints sensíveis, inseguras (ex: sem autenticação ou expostas diretamente no frontend).

        4. Autenticação

        Analise como a autenticação é feita. Tokens estão expostos? Há uso inseguro de localStorage, sessionStorage ou cookies?

        5. Autorização

        Existe verificação de permissões no frontend? Funcionalidades estão protegidas corretamente ou acessíveis sem validação?

        6. Lógica sensível no frontend

        A lógica de negócio crítica está implementada somente no cliente?

        7. Problemas comuns de segurança em React

        Verifique uso de dangerouslySetInnerHTML, eval, bibliotecas inseguras, uso de dados do usuário sem sanitização (potencial XSS), etc.

        Para cada item com problemas, inclua:

        Descrição resumida do problema

        Localização no código (linha, função ou trecho)

        Criticidade (Baixa, Média, Alta)

        Sugestão de mitigação

        Código a ser analisado:
        "{js_code}"
    """


def get_analyse_regex_findings_prompt(js_code):
    findings = find_secrets(js_code)
    return f"""
            Você é um especialista em segurança de aplicações web. Abaixo está uma lista de strings extraídas de um código JavaScript/React por expressões regulares. Analise cada string e retorne apenas aquelas que representam um possível risco de segurança.

            Ignore qualquer string que for inofensiva.
            
            As strings estarão separadas por ]] no final delas.

            Para cada string considerada perigosa ou suspeita, responda neste formato:

            String: <conteúdo da string>

            Tipo identificado: (ex: chave de API, token JWT, rota admin, URL sensível, segredo, etc.)

            Descrição do risco: breve e objetiva

            Nível de criticidade: (Baixo, Médio, Alto)

            Sugestão de mitigação: (se aplicável)

            Strings extraídas:
            {"]]".join(findings)}
    """


def analyze_with_llm(prompt):
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)
    return response.text


def analyze_file(js_code):
    regex_findings = find_secrets(js_code)
    analyse_code_prompt = get_analyse_code_prompt(js_code)
    analyse_regex_findings_prompt = get_analyse_regex_findings_prompt(js_code)
    code_llm_response = analyze_with_llm(analyse_code_prompt)
    regex_llm_response = analyze_with_llm(analyse_regex_findings_prompt)
    return {
        "regex_findings": regex_findings,
        "code_llm_response": code_llm_response,
        "regex_llm_response": regex_llm_response,
    }


