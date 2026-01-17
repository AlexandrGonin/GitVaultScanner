import os
import re
import sys
import tempfile
import subprocess
import argparse
from datetime import datetime
from pathlib import Path

banner = """
    ╔════════════════════════════════════════════════════════════════╗
    ║                                                                ║
    ║   █▀▀ █ ▀█▀ █░█ ▄▀█ █░█ █░░ ▀█▀ █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█   ║
    ║   █▄█ █ ░█░ ▀▄▀ █▀█ █▄█ █▄▄ ░█░ ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄   ║
    ║                                                                ║
    ║         GitHub & Local Directory Secrets Scanner               ║
    ║         Detects hardcoded credentials, API keys, tokens        ║
    ╚════════════════════════════════════════════════════════════════╝

    
    """

def print_banner(banner):
    # Вывод баннера программы в консоль
    print(banner)


def clone_repo(repo_url, target_dir):
    # Клонирование GitHub репозитория во временную директорию
    try:
        print(f"Cloning repository...")
        subprocess.run(['git', 'clone', repo_url, target_dir], 
                      check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e.stderr}")
        return False


def scan_local_directory(dir_path):
    # Сканирование локальной директории для проверки существования
    dir_path = os.path.abspath(dir_path)
    if not os.path.exists(dir_path):
        print(f"Directory not found: {dir_path}")
        return None
    if not os.path.isdir(dir_path):
        print(f"Path is not a directory: {dir_path}")
        return None
    return dir_path


def get_all_files(root_dir, include_extensions='all'):
    # Получение списка всех файлов в директории с фильтрацией
    files = []
    for root, dirs, filenames in os.walk(root_dir):
        # Пропускаем скрытые директории и директории зависимостей
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('__pycache__', 'venv', 'env', 'node_modules', '.git', '.idea')]
        
        for filename in filenames:
            if include_extensions == 'all' or any(filename.endswith(ext) for ext in include_extensions):
                files.append(os.path.join(root, filename))
    return files    


def scan_file(file_path):
    # Сканирование одного файла на наличие захардкоженных секретов
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        return []

    # Получаем расширение файла для контекстного анализа
    file_ext = os.path.splitext(file_path)[1].lower()
    
    lines = content.split('\n')
    findings = []

    # Регулярное выражение для поиска присваиваний переменных
    assignment_regex = re.compile(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*[\'"]([^\'"]+)[\'"]')
    
    # Паттерн для JSON, YAML и конфигурационных файлов
    json_yaml_pattern = r'[\'"](password|passwd|pwd|token|secret|key|api_key|secret_key|access_key)[\'"]\s*:\s*[\'"]([^\'"]+)[\'"]'

    # Паттерны для строк подключения к базам данных
    db_patterns = [
        r'postgres(ql)?://[^:\s]+:[^@\s]+@[^\s]+',
        r'mysql://[^:\s]+:[^@\s]+@[^\s]+',
        r'mongodb(\+srv)?://[^:\s]+:[^@\s]+@[^\s]+',
        r'redis://[^:\s]+:[^@\s]+@[^\s]+',
        r'rediss://[^:\s]+:[^@\s]+@[^\s]+',
        r'sqlite:///[^\s]+',
        r'Driver=[^;]+;.*PWD=[^;]+',
        r'Data Source=[^;]+;.*Password=[^;]+',
    ]

    # Паттерн для URL с учетными данными
    url_with_creds_pattern = r'https?://[^:\s]+:[^@\s]+@[^\s]+'
    
    # Паттерны для функций с параметрами паролей
    function_patterns = [
        r'\.?connect\s*\([^)]*password\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'\.?connect\s*\([^)]*passwd\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'\.?connect\s*\([^)]*pwd\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'\.?getConnection\s*\([^)]*password\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'\.?create_engine\s*\([^)]*password\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'Client\s*\([^)]*password\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'client\s*\([^)]*password\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'\.?authenticate\s*\([^)]*password\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'\.?login\s*\([^)]*password\s*=\s*[\'"]([^\'"]+)[\'"]',
    ]

    # Паттерн для словарей с секретами
    dict_pattern = r'[\'"](password|passwd|pwd|token|secret|key)[\'"]\s*:\s*[\'"]([^\'"]+)[\'"]'
    
    # Паттерны для API ключей различных сервисов
    api_key_patterns = [
        r'(sk|pk)_[a-zA-Z0-9]{24,}',
        r'[a-f0-9]{32}',
        r'[A-Z0-9]{40}',
        r'gh[pousr]_[A-Za-z0-9_]{36}',
        r'[a-zA-Z0-9_-]{43,44}',
        r'xox[pbar]-[A-Za-z0-9]{10,48}',
        r'sq0[a-z]{3}-[0-9A-Za-z\-_]{43}',
    ]

    # Обработка каждой строки файла
    for line_number, line in enumerate(lines, 1):
        stripped_line = line.strip()
        
        # Пропускаем комментарии в зависимости от типа файла
        if file_ext == '.py':
            if stripped_line.startswith('#') or stripped_line.startswith('"""'):
                continue
        elif file_ext in ['.json', '.yml', '.yaml', '.ini', '.cfg', '.conf']:
            if stripped_line.startswith('#') or stripped_line.startswith('//'):
                continue
        
        # Пропускаем ссылки на переменные окружения
        if 'os.getenv' in line or 'dotenv_values' in line or 'environ.get' in line:
            continue

        # Поиск паттернов присваивания переменных
        match = assignment_regex.search(line)
        if match:
            var_name, value = match.groups()
            if len(value) >= 8:
                # Список ключевых слов, указывающих на секретные данные
                secret_patterns = [
                    r'key', r'secret', r'token', r'password', r'passwd', r'pwd',
                    r'api[_-]?key', r'auth', r'credential', r'private',
                    r'database', r'host', r'port', r'user', r'username',
                    r'cert', r'ssl', r'tls', r'ssh',
                    r'access[_-]?key', r'client[_-]?id', r'consumer[_-]?key',
                    r'bearer', r'jwt', r'oauth', r'app[_-]?secret',
                    r'encryption[_-]?key', r'private[_-]?key'
                ]

                var_lower = var_name.lower()
                # Проверяем, содержит ли имя переменной ключевые слова секретов
                is_secret_like = any(re.search(pattern, var_lower) for pattern in secret_patterns)

                # Проверяем, выглядит ли значение как секрет
                looks_like_secret = (
                    len(value) >= 12 or
                    (any(c.isupper() for c in value) and any(c.islower() for c in value) and any(c.isdigit() for c in value)) or
                    bool(re.search(r'[^a-zA-Z0-9\s]', value))
                )

                # Если есть признаки секрета, добавляем в результаты
                if is_secret_like or looks_like_secret:
                    severity = '🔴 HIGH' if (is_secret_like and looks_like_secret) else '🟡 MEDIUM'
                    
                    findings.append({
                        'file': os.path.relpath(file_path),
                        'line': line_number,
                        'type': 'Variable Assignment',
                        'variable': var_name,
                        'value': value,
                        'severity': severity
                    })

        # Поиск API ключей по паттернам
        try:
            for pattern in api_key_patterns:
                for match in re.finditer(pattern, line, re.IGNORECASE):
                    if match.group():
                        api_key = match.group()
                        findings.append({
                            'file': os.path.relpath(file_path),
                            'line': line_number,
                            'type': 'API Key Pattern',
                            'variable': 'Potential API key',
                            'value': api_key[:50] + ('...' if len(api_key) > 50 else ''),
                            'severity': '🔴 HIGH'
                        })
        except re.error:
            continue

        # Поиск строк подключения к базам данных
        try:
            for pattern in db_patterns:
                for match in re.finditer(pattern, line, re.IGNORECASE):
                    if match.group():
                        url = match.group()
                        password = None
                        # Извлекаем пароль из URL
                        password_match = re.search(r':([^:@]+)@', url)
                        if password_match:
                            password = password_match.group(1)
                        
                        findings.append({
                            'file': os.path.relpath(file_path),
                            'line': line_number,
                            'type': 'Database URL',
                            'variable': 'Database connection URL',
                            'value': url[:100] + ('...' if len(url) > 100 else ''),
                            'severity': '🔴 HIGH',
                            'password': password
                        })
        except re.error:
            continue

        # Поиск URL с учетными данными
        try:
            for match in re.finditer(url_with_creds_pattern, line, re.IGNORECASE):
                if match.group():
                    url = match.group()
                    password_match = re.search(r':([^:@]+)@', url)
                    password = password_match.group(1) if password_match else None
                    
                    findings.append({
                        'file': os.path.relpath(file_path),
                        'line': line_number,
                        'type': 'URL with Credentials',
                        'variable': 'URL with embedded credentials',
                        'value': url[:100] + ('...' if len(url) > 100 else ''),
                        'severity': '🔴 HIGH',
                        'password': password
                    })
        except re.error:
            continue

        # Поиск паролей в параметрах функций
        try:
            for pattern in function_patterns:
                for match in re.finditer(pattern, line, re.IGNORECASE):
                    if match.groups():
                        password = match.group(1)
                        if len(password) >= 4:
                            # Получаем контекст функции
                            func_context = line[:match.start()].split('(')[-1].strip()
                            
                            findings.append({
                                'file': os.path.relpath(file_path),
                                'line': line_number,
                                'type': 'Function Parameter',
                                'variable': f'Password parameter in {func_context}',
                                'value': password,
                                'severity': '🔴 HIGH'
                            })
        except re.error:
            continue

        # Поиск секретов в словарях и конфигурационных файлах
        try:
            # Проверка паттернов словарей
            for match in re.finditer(dict_pattern, line, re.IGNORECASE):
                if match.groups():
                    key, value = match.groups()
                    if len(value) >= 6:
                        findings.append({
                            'file': os.path.relpath(file_path),
                            'line': line_number,
                            'type': 'Dictionary Key',
                            'variable': f'Dictionary key: {key}',
                            'value': value,
                            'severity': '🟡 MEDIUM' if key == 'key' else '🔴 HIGH'
                        })
            
            # Проверка JSON/YAML паттернов
            for match in re.finditer(json_yaml_pattern, line, re.IGNORECASE):
                if match.groups():
                    key, value = match.groups()
                    if len(value) >= 6:
                        findings.append({
                            'file': os.path.relpath(file_path),
                            'line': line_number,
                            'type': 'Config Key',
                            'variable': f'Config key: {key}',
                            'value': value,
                            'severity': '🔴 HIGH'
                        })
        except re.error:
            continue

    return findings


def print_console_results(findings, target_name, scan_time, scan_type):
    # Вывод результатов сканирования в консоль с форматированием
    
    print("\n" + "═" * 70)
    print(f"SCAN RESULTS ({scan_type})")
    print("═" * 70)
    
    # Если не найдено секретов
    if not findings:
        print(f"\nNo hardcoded secrets found in '{target_name}'")
        print(f"\nScan completed in {scan_time:.2f} seconds")
        return

    # Подсчет общего количества и классификация по уровням риска
    total_findings = len(findings)
    high_count = len([f for f in findings if '🔴' in f['severity']])
    medium_count = len([f for f in findings if '🟡' in f['severity']])
    
    # Вывод сводной информации
    print(f"\nTarget: {target_name}")
    print(f"Summary:")
    print(f"   ├─ Total findings: {total_findings}")
    print(f"   ├─ 🔴 High risk: {high_count}")
    print(f"   └─ 🟡 Medium risk: {medium_count}")
    
    print("\nDETAILED FINDINGS")
    print("─" * 70)
    
    # Группировка находок по уровню риска
    high_findings = [f for f in findings if '🔴' in f['severity']]
    medium_findings = [f for f in findings if '🟡' in f['severity']]
    
    # Вывод находок высокого риска
    if high_findings:
        print("\n🔴 HIGH RISK FINDINGS:")
        print("─" * 40)
        for i, finding in enumerate(high_findings, 1):
            print(f"\n{i}. {finding['file']}:{finding['line']}")
            print(f"   Type: {finding['type']}")
            print(f"   Variable: {finding['variable']}")
            if finding.get('password'):
                print(f"   Password found: {finding['password'][:20]}...")
            print(f"   Value: {finding['value'][:80]}")
    
    # Вывод находок среднего риска
    if medium_findings:
        print("\n🟡 MEDIUM RISK FINDINGS:")
        print("─" * 40)
        for i, finding in enumerate(medium_findings, 1):
            print(f"\n{i}. {finding['file']}:{finding['line']}")
            print(f"   Type: {finding['type']}")
            print(f"   Variable: {finding['variable']}")
            print(f"   Value: {finding['value'][:80]}")

    print(f"\nScan completed in {scan_time:.2f} seconds")
    
    # Вывод предупреждения если есть находки высокого риска
    if high_count > 0:
        print("\n" + "⚠" * 70)
        print(f"⚠️  WARNING: {high_count} HIGH RISK SECRETS FOUND!")
        print(f"⚠️  Immediate action required!")
        print("⚠" * 70)


def save_to_file(findings, target_name, scan_time, output_file, scan_type):
    # Сохранение результатов сканирования в текстовый файл
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("GITVAULT SCANNER - SECURITY AUDIT REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Scan type: {scan_type}\n")
        f.write(f"Target: {target_name}\n")
        f.write(f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Scan duration: {scan_time:.2f} seconds\n")
        
        # Если не найдено секретов
        if not findings:
            f.write("\n" + "=" * 80 + "\n")
            f.write("RESULT: NO SECRETS FOUND\n")
            f.write("=" * 80 + "\n")
            return
        
        # Подсчет статистики
        total = len(findings)
        high = len([x for x in findings if '🔴' in x['severity']])
        medium = len([x for x in findings if '🟡' in x['severity']])
        
        # Запись сводной информации
        f.write(f"\nSUMMARY\n")
        f.write("-" * 40 + "\n")
        f.write(f"Total findings: {total}\n")
        f.write(f"High risk: {high}\n")
        f.write(f"Medium risk: {medium}\n")
        
        # Запись детальной информации
        f.write("\n" + "=" * 80 + "\n")
        f.write("DETAILED FINDINGS\n")
        f.write("=" * 80 + "\n\n")
        
        for i, finding in enumerate(findings, 1):
            f.write(f"[{i}] {finding['severity']} - {finding['type']}\n")
            f.write(f"    File: {finding['file']}\n")
            f.write(f"    Line: {finding['line']}\n")
            f.write(f"    Variable: {finding['variable']}\n")
            if finding.get('password'):
                f.write(f"    Password: {finding['password']}\n")
            f.write(f"    Value: {finding['value']}\n")
            f.write("-" * 60 + "\n")
        
        # Запись критического предупреждения
        if high > 0:
            f.write("\n" + "!" * 80 + "\n")
            f.write(f"CRITICAL: {high} HIGH RISK SECRETS FOUND\n")
            f.write("IMMEDIATE ACTION REQUIRED!\n")
            f.write("!" * 80 + "\n")
    
    print(f"\nReport saved to: {output_file}")


def main():
    # Основная функция программы
    parser = argparse.ArgumentParser(
        description='GitVault Scanner - Advanced secrets scanner for GitHub repositories and local directories',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --repo https://github.com/user/repo
  %(prog)s --dir /path/to/directory
  %(prog)s --repo https://github.com/user/repo --output scan_report.txt
  %(prog)s --dir . --output local_scan.txt --extensions .py .json .yaml
        """
    )
    
    # Создание взаимно исключающей группы для типов сканирования
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--repo', '-r', help='GitHub repository URL')
    group.add_argument('--dir', '-d', help='Local directory path')
    
    # Дополнительные аргументы командной строки
    parser.add_argument('--output', '-o', help='Save report to file')
    parser.add_argument('--extensions', '-e', nargs='+', default='all',
                       help='File extensions to scan (default: all files). Use specific extensions like .py .json')
    parser.add_argument('--no-clone-cleanup', action='store_true',
                       help='Keep cloned repository after scan (for debugging)')
    
    args = parser.parse_args()
    
    print_banner(banner)
    
    start_time = datetime.now()
    findings = []
    scan_type = ""
    target_name = ""

    # Обработка сканирования GitHub репозитория
    if args.repo:
        repo_url = args.repo
        
        # Проверка валидности URL GitHub
        if not repo_url.startswith('https://github.com/'):
            print("Error: Please provide a valid GitHub URL starting with https://github.com/")
            sys.exit(1)

        # Извлечение имени репозитория из URL
        target_name = repo_url.split('/')[-1]
        if target_name.endswith('.git'):
            target_name = target_name[:-4]
        
        print(f"\nRepository: {repo_url}")
        print("─" * 50)
        
        # Определение директории для клонирования
        if args.no_clone_cleanup:
            # Используем текущую директорию
            repo_dir = os.path.join(os.getcwd(), target_name)
            print(f"Cloning to: {repo_dir}")
        else:
            # Используем временную директорию
            temp_dir = tempfile.mkdtemp(prefix="gvs_")
            repo_dir = os.path.join(temp_dir, target_name)
            print(f"Using temporary directory: {temp_dir}")
    
        # Клонирование репозитория
        if not clone_repo(repo_url, repo_dir):
            print("Failed to clone repository")
            sys.exit(1)
        
        print(f"Repository cloned successfully")
        scan_type = "GitHub Repository Scan"
        
    # Обработка сканирования локальной директории
    elif args.dir:
        target_name = os.path.abspath(args.dir)
        repo_dir = scan_local_directory(args.dir)
        if not repo_dir:
            sys.exit(1)
        
        print(f"\nDirectory: {target_name}")
        print("─" * 50)
        scan_type = "Local Directory Scan"
        
        if args.no_clone_cleanup:
            print(f"Scanning directory in place")
        else:
            print(f"Scanning directory directly")
    
    # Получение списка файлов для сканирования
    extensions = args.extensions
    if extensions == 'all' or (isinstance(extensions, list) and 'all' in extensions):
        print(f"Scanning all files in target...")
        files = get_all_files(repo_dir, include_extensions='all')
    else:
        print(f"Scanning files with extensions: {', '.join(extensions)}")
        files = get_all_files(repo_dir, include_extensions=extensions)
    
    # Проверка наличия файлов для сканирования
    if not files:
        print("No files found matching the criteria")
        sys.exit(0)
    
    print(f"Found {len(files)} files to scan")
    print("Scanning files...")
    
    # Сканирование каждого файла
    for i, file_path in enumerate(files, 1):
        if i % 10 == 0 or i == len(files):
            print(f"   Scanning file {i}/{len(files)}...", end='\r')
        file_findings = scan_file(file_path)
        findings.extend(file_findings)
    
    print()  # Новая строка после индикатора прогресса
    
    # Расчет времени сканирования
    scan_time = (datetime.now() - start_time).total_seconds()
    
    # Вывод результатов в консоль
    print_console_results(findings, target_name, scan_time, scan_type)
    
    # Сохранение результатов в файл если указан аргумент
    if args.output:
        save_to_file(findings, target_name, scan_time, args.output, scan_type)
    
    # Очистка временных файлов если нужно
    if not args.no_clone_cleanup and args.repo:
        try:
            import shutil
            temp_parent = os.path.dirname(repo_dir)
            if os.path.exists(temp_parent) and temp_parent.startswith(tempfile.gettempdir()):
                shutil.rmtree(temp_parent)
                print(f"Temporary files cleaned up")
        except Exception as e:
            print(f"⚠️  Warning: Could not clean up temporary files: {e}")
    
    # Установка кода выхода на основе результатов
    high_count = len([f for f in findings if '🔴' in f['severity']])
    if high_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()