# Burp Recon

Transforma exports XML do Burp Suite em um conjunto sanitizado de recon e em
um arquivo draw.io editável com quatro páginas:

- fluxo observado/descoberto do site;
- arquitetura por host, papel, serviço e dependências;
- tecnologias e sinais que sustentam a detecção;
- mapa de endpoints agrupado por host e serviço.

## Uso

Primeiro gere o inventário. É possível passar um ou vários exports do Burp:

```bash
python3 burp_recon_summary.py captura-login.xml captura-app.xml \
  -o resultado --project-name "Meu projeto"
```

Depois gere o diagrama:

```bash
python3 recon_to_drawio.py resultado -o resultado/arquitetura.drawio
```

Abra o `.drawio` em <https://app.diagrams.net/> ou no aplicativo draw.io.

Para incluir JavaScript, CSS, imagens e outros assets no inventário completo:

```bash
python3 burp_recon_summary.py captura.xml -o resultado --include-static
```

## Saídas principais

- `endpoints.csv` e `ENDPOINTS.md`: endpoints normalizados;
- `hosts.csv`: hosts, IPs vistos, papéis e tecnologias;
- `services.csv`: agrupamento funcional das rotas;
- `flows.csv`: redirects, referers, forms e links descobertos;
- `technologies.csv`: tecnologia, categoria, confiança, versão e evidência;
- `requests.csv`: sequência sanitizada das requisições;
- `summary.json`: entrada estruturada para automações;
- `security_headers.csv`, `cookies.csv` e `findings.csv`: revisão HTTP.

## Tratamento de dados sensíveis

O relatório não grava bodies completos, senhas, tokens nem valores de cookies.
Valores de query string são substituídos por placeholders e identificadores
dinâmicos em URLs são convertidos para `{jwt}`, `{uuid}`, `{opaque_id}` etc.

Os resultados são inferências baseadas somente no tráfego fornecido: uma
tecnologia ou um backend não observado não é tratado como fato.
