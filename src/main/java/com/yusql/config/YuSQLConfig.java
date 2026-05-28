package com.yusql.config;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

public class YuSQLConfig {

    private static final Path DIR = Paths.get(System.getProperty("user.home"), ".yusql");

    // --- General settings ---
    private int threadCount = 5, maxQueueSize = 500;
    private boolean deduplicateTasks = true;

    // --- Module toggles ---
    private boolean enableError = true, enableBoolean = true, enableOrder = true, enableOrderInjection = true;

    // --- Monitor ---
    private boolean monitorProxy, monitorRepeater;

    // --- Filters ---
    private boolean enableDomainWl, enableDomainBl = true, enableUrlBl = true;
    private boolean enableParamWl, enableParamBl = true;

    // --- JSON ---
    private boolean enableJsonValue = true, enableJsonInParam = true;

    // --- Compare ---
    private double similarityThreshold = 0.95, lengthDiffRatio = 0.10;
    private int lengthDiffAbs = 50;
    private boolean removeWhitespace;

    // --- Error injection ---
    private boolean enableCustomErrorPocs = true, blockBuiltinQuotePocs = true;

    // --- URL encode chars for GET append params ---
    private boolean enableUrlEncodeChars = true;
    private String urlEncodeChars = "{}[]";

    // Rule caches
    private final List<Pattern> errorPatterns = new CopyOnWriteArrayList<>();
    private final List<Map.Entry<String, String>> appendParams = new ArrayList<>();
    private final Map<String, Integer> appendParamGroups = new LinkedHashMap<>();
    private final Set<String> orderInjectionParams = new LinkedHashSet<>();
    private final List<Pattern> noiseRegexes = new CopyOnWriteArrayList<>();
    private final List<Pattern> paramWhitelist = new CopyOnWriteArrayList<>();
    private final List<Pattern> paramBlacklist = new CopyOnWriteArrayList<>();
    private final List<Pattern> urlBlacklist = new CopyOnWriteArrayList<>();
    private final List<String> domainWhitelist = new CopyOnWriteArrayList<>();
    private final List<String> domainBlacklist = new CopyOnWriteArrayList<>();
    private final List<Map.Entry<String, String>> customHeaders = new ArrayList<>();

    private final List<Runnable> listeners = new ArrayList<>();
    public void onChange(Runnable r) { listeners.add(r); }

    public YuSQLConfig() {
        ensureDir();
        resetNoiseRegexToDefaults();
        loadAll();
    }
    public Path dir() { return DIR; }
    private void ensureDir() { try { Files.createDirectories(DIR); } catch (IOException e) {} }
    private void resetNoiseRegexToDefaults() { savePatterns(path("SQL_noise_regex.ini"), defaultNoisePatterns()); }

    // =========================================================================
    // Load all configs
    // =========================================================================
    public List<String> loadAll() {
        List<String> errors = new ArrayList<>();
        ensureDir();
        loadSettings(errors);
        errorPatterns.clear(); errorPatterns.addAll(loadPatterns(path("SQL_diy_error.ini"), errors, true));
        appendParams.clear(); appendParams.addAll(loadAppendParams(errors));
        appendParamGroups.clear(); appendParamGroups.putAll(loadParamGroups(errors));
        orderInjectionParams.clear(); orderInjectionParams.addAll(loadLines(path("SQL_order_injection_params.ini"), errors));
        noiseRegexes.clear(); noiseRegexes.addAll(loadPatterns(path("SQL_noise_regex.ini"), errors, true));
        paramWhitelist.clear(); paramWhitelist.addAll(loadPatterns(path("SQL_param_whitelist.ini"), errors, false));
        paramBlacklist.clear(); paramBlacklist.addAll(loadPatterns(path("SQL_param_blacklist.ini"), errors, true));
        urlBlacklist.clear(); urlBlacklist.addAll(loadPatterns(path("SQL_url_blacklist.ini"), errors, true));
        domainWhitelist.clear(); domainWhitelist.addAll(loadLines(path("SQL_domain_whitelist.ini"), errors));
        domainBlacklist.clear(); domainBlacklist.addAll(loadLines(path("SQL_domain_blacklist.ini"), errors));
        customHeaders.clear(); customHeaders.addAll(loadCustomHeaders(errors));
        createDefaultsIfMissing();
        // Reload any configs that were empty because defaults were just created
        if (errorPatterns.isEmpty()) { errorPatterns.addAll(loadPatterns(path("SQL_diy_error.ini"), errors, true)); }
        if (appendParams.isEmpty()) { appendParams.addAll(loadAppendParams(errors)); }
        if (noiseRegexes.isEmpty()) { noiseRegexes.addAll(loadPatterns(path("SQL_noise_regex.ini"), errors, true)); }
        if (paramBlacklist.isEmpty()) { paramBlacklist.addAll(loadPatterns(path("SQL_param_blacklist.ini"), errors, true)); }
        if (urlBlacklist.isEmpty()) { urlBlacklist.addAll(loadPatterns(path("SQL_url_blacklist.ini"), errors, true)); }
        if (customHeaders.isEmpty()) { customHeaders.addAll(loadCustomHeaders(errors)); }
        return errors;
    }

    private void createDefaultsIfMissing() {
        if (!Files.exists(path("SQL_diy_error.ini"))) savePatterns(path("SQL_diy_error.ini"), defaultErrorPatterns());
        if (!Files.exists(path("SQL_append_params.ini"))) saveAppendParamsToFile(defaultAppendParams());
        if (!Files.exists(path("SQL_noise_regex.ini"))) savePatterns(path("SQL_noise_regex.ini"), defaultNoisePatterns());
        if (!Files.exists(path("SQL_param_blacklist.ini"))) savePatterns(path("SQL_param_blacklist.ini"), defaultParamBlPatterns());
        if (!Files.exists(path("SQL_url_blacklist.ini"))) savePatterns(path("SQL_url_blacklist.ini"), defaultUrlBlPatterns());
        for (String f : new String[]{"SQL_param_whitelist.ini","SQL_domain_whitelist.ini","SQL_domain_blacklist.ini",
                                           "SQL_append_params_groups.ini"})
            if (!Files.exists(path(f))) writeString(path(f), "# One rule per line\n");
        if (!Files.exists(path("SQL_order_injection_params.ini"))) saveOrderInjectionParamsToFile(defaultOrderInjectionParams());
        if (!Files.exists(path("SQL_error_pocs.ini"))) writeString(path("SQL_error_pocs.ini"), "\\");
        if (!Files.exists(path("SQL_custom_headers.ini"))) writeString(path("SQL_custom_headers.ini"), "Range: bytes=0-1000");
    }

    // =========================================================================
    // Settings load/save
    // =========================================================================
    private void loadSettings(List<String> errors) {
        Path p = path("SQL_settings.ini");
        if (!Files.exists(p)) { saveSettings(); return; }
        Properties props = new Properties();
        try (Reader r = Files.newBufferedReader(p, StandardCharsets.UTF_8)) { props.load(r); }
        catch (IOException e) { errors.add("load settings: " + e.getMessage()); return; }

        threadCount         = ip(props, "general.thread_count", 5);
        maxQueueSize        = ip(props, "general.max_queue_size", 500);
        deduplicateTasks    = bp(props, "general.deduplicate_tasks", true);

        enableError         = bp(props, "modules.enable_error_injection", true);
        enableBoolean       = bp(props, "modules.enable_boolean_injection", true);
        enableOrder         = bp(props, "modules.enable_order_test", true);
        enableOrderInjection = bp(props, "modules.enable_order_injection", true);

        monitorProxy        = false; // Always off on restart to avoid accidental scanning
        monitorRepeater     = false;

        enableDomainWl      = bp(props, "filter.enable_domain_whitelist", false);
        enableDomainBl      = bp(props, "filter.enable_domain_blacklist", true);
        enableUrlBl         = bp(props, "filter.enable_url_blacklist", true);
        enableParamWl       = bp(props, "filter.enable_param_whitelist", false);
        enableParamBl       = bp(props, "filter.enable_param_blacklist", true);

        enableJsonValue     = bp(props, "json.enable_json_value_test", true);
        enableJsonInParam   = bp(props, "json.enable_json_in_param", true);

        similarityThreshold = dp(props, "compare.similarity_threshold", 0.95);
        lengthDiffRatio     = dp(props, "compare.length_diff_ratio", 0.10);
        lengthDiffAbs       = ip(props, "compare.length_diff_abs", 50);
        removeWhitespace    = bp(props, "compare.remove_whitespace", false);

        enableCustomErrorPocs  = bp(props, "error_injection.enable_custom_error_pocs", true);
        blockBuiltinQuotePocs  = bp(props, "error_injection.block_builtin_quote_pocs", true);

        enableUrlEncodeChars  = bp(props, "order.url_encode_chars_enabled", true);
        urlEncodeChars        = sp(props, "order.url_encode_chars", "{}[]");
    }

    public void saveSettings() {
        ensureDir();
        Properties p = new Properties();
        p.setProperty("general.thread_count",               ""+threadCount);
        p.setProperty("general.max_queue_size",             ""+maxQueueSize);
        p.setProperty("general.deduplicate_tasks",          ""+deduplicateTasks);
        p.setProperty("modules.enable_error_injection",     ""+enableError);
        p.setProperty("modules.enable_boolean_injection",   ""+enableBoolean);
        p.setProperty("modules.enable_order_test",          ""+enableOrder);
        p.setProperty("modules.enable_order_injection",   ""+enableOrderInjection);
        p.setProperty("monitor.monitor_proxy",              ""+monitorProxy);
        p.setProperty("monitor.monitor_repeater",           ""+monitorRepeater);
        p.setProperty("filter.enable_domain_whitelist",     ""+enableDomainWl);
        p.setProperty("filter.enable_domain_blacklist",     ""+enableDomainBl);
        p.setProperty("filter.enable_url_blacklist",        ""+enableUrlBl);
        p.setProperty("filter.enable_param_whitelist",      ""+enableParamWl);
        p.setProperty("filter.enable_param_blacklist",      ""+enableParamBl);
        p.setProperty("json.enable_json_value_test",        ""+enableJsonValue);
        p.setProperty("json.enable_json_in_param",          ""+enableJsonInParam);
        p.setProperty("compare.similarity_threshold",       ""+similarityThreshold);
        p.setProperty("compare.length_diff_ratio",          ""+lengthDiffRatio);
        p.setProperty("compare.length_diff_abs",            ""+lengthDiffAbs);
        p.setProperty("compare.remove_whitespace",          ""+removeWhitespace);
        p.setProperty("error_injection.enable_custom_error_pocs", ""+enableCustomErrorPocs);
        p.setProperty("error_injection.block_builtin_quote_pocs", ""+blockBuiltinQuotePocs);
        p.setProperty("order.url_encode_chars_enabled", ""+enableUrlEncodeChars);
        p.setProperty("order.url_encode_chars", urlEncodeChars);
        try (Writer w = Files.newBufferedWriter(path("SQL_settings.ini"), StandardCharsets.UTF_8)) {
            p.store(w, "YuSQL V5");
        } catch (IOException e) {}
    }

    // =========================================================================
    // Rule file loaders
    // =========================================================================
    private List<Pattern> loadPatterns(Path f, List<String> errors, boolean writeDefault) {
        List<Pattern> list = new ArrayList<>();
        if (!Files.exists(f)) return list;
        try {
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                try { list.add(Pattern.compile(decodeHexEscapes(line))); }
                catch (PatternSyntaxException e) { errors.add("Bad regex in "+f.getFileName()+": "+line); }
            }
        } catch (IOException e) { errors.add("read "+f.getFileName()+": "+e.getMessage()); }
        return list;
    }

    private List<Map.Entry<String,String>> loadAppendParams(List<String> errors) {
        List<Map.Entry<String,String>> list = new ArrayList<>();
        Path f = path("SQL_append_params.ini");
        if (!Files.exists(f)) return list;
        try {
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int idx = line.indexOf(':');
                if (idx > 0) { String k=line.substring(0,idx).strip(), v=line.substring(idx+1).strip();
                    if (!k.isEmpty() && !v.isEmpty()) list.add(new AbstractMap.SimpleEntry<>(k, v)); }
            }
        } catch (IOException e) { errors.add("read append_params: "+e.getMessage()); }
        return list;
    }

    private List<String> loadLines(Path f, List<String> errors) {
        List<String> list = new ArrayList<>();
        if (!Files.exists(f)) return list;
        try {
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                line = line.strip();
                if (!line.isEmpty() && !line.startsWith("#")) list.add(line);
            }
        } catch (IOException e) { errors.add("read "+f.getFileName()+": "+e.getMessage()); }
        return list;
    }

    private Map<String,Integer> loadParamGroups(List<String> errors) {
        Map<String,Integer> m = new LinkedHashMap<>();
        Path f = path("SQL_append_params_groups.ini");
        if (!Files.exists(f)) return m;
        try {
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int idx = line.indexOf(':');
                if (idx > 0) {
                    String k = line.substring(0, idx).strip();
                    try {
                        int v = Integer.parseInt(line.substring(idx + 1).strip());
                        if (!k.isEmpty() && v > 0) m.put(k, v);
                    } catch (NumberFormatException ignored) {}
                }
            }
        } catch (IOException e) { errors.add("read "+f.getFileName()+": "+e.getMessage()); }
        return m;
    }

    private List<Map.Entry<String,String>> loadCustomHeaders(List<String> errors) {
        List<Map.Entry<String,String>> list = new ArrayList<>();
        Path f = path("SQL_custom_headers.ini");
        if (!Files.exists(f)) return list;
        try {
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int idx = line.indexOf(':');
                if (idx > 0) {
                    String k = line.substring(0, idx).strip();
                    String v = line.substring(idx + 1).strip();
                    if (!k.isEmpty()) list.add(new AbstractMap.SimpleEntry<>(k, v));
                }
            }
        } catch (IOException e) { errors.add("read custom_headers: " + e.getMessage()); }
        return list;
    }

    public void saveCustomHeaders(List<Map.Entry<String,String>> headers) {
        customHeaders.clear();
        customHeaders.addAll(headers);
        ensureDir();
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(path("SQL_custom_headers.ini"), StandardCharsets.UTF_8))) {
            for (var e : headers) pw.println(e.getKey() + ": " + e.getValue());
        } catch (IOException e) {}
    }

    // =========================================================================
    // Savers
    // =========================================================================
    private void savePatterns(Path f, List<Pattern> list) {
        ensureDir();
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(f, StandardCharsets.UTF_8))) {
            for (Pattern p : list) pw.println(p.pattern());
        } catch (IOException e) {}
    }
    private void saveAppendParamsToFile(List<Map.Entry<String,String>> list) {
        ensureDir();
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(path("SQL_append_params.ini"), StandardCharsets.UTF_8))) {
            for (var e : list) pw.println(e.getKey()+":"+e.getValue());
        } catch (IOException ex) {}
    }
    private void saveOrderInjectionParamsToFile(Set<String> params) {
        ensureDir();
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(path("SQL_order_injection_params.ini"), StandardCharsets.UTF_8))) {
            for (String k : params) pw.println(k);
        } catch (IOException e) {}
    }
    public void saveAppendParamGroups(Map<String, Integer> groups) {
        appendParamGroups.clear();
        appendParamGroups.putAll(groups);
        ensureDir();
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(path("SQL_append_params_groups.ini"), StandardCharsets.UTF_8))) {
            for (var e : groups.entrySet()) {
                if (e.getValue() > 0) pw.println(e.getKey() + ":" + e.getValue());
            }
        } catch (IOException ex) {}
    }

    public void saveOrderInjectionParams(Set<String> params) {
        orderInjectionParams.clear();
        orderInjectionParams.addAll(params);
        ensureDir();
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(path("SQL_order_injection_params.ini"), StandardCharsets.UTF_8))) {
            for (String k : params) pw.println(k);
        } catch (IOException e) {}
    }
    private void writeString(Path f, String s) {
        try { Files.writeString(f, s, StandardCharsets.UTF_8); } catch (IOException e) {}
    }

    // =========================================================================
    // V5 Default patterns
    // =========================================================================
    private List<Pattern> defaultErrorPatterns() {
        return Arrays.stream(V5_DEFAULT_ERROR_PATTERNS).map(Pattern::compile).collect(Collectors.toList());
    }
    private List<Map.Entry<String,String>> defaultAppendParams() {
        List<Map.Entry<String,String>> list = new ArrayList<>();
        for (String line : V5_DEFAULT_APPEND_PARAMS) {
            int idx = line.indexOf(':');
            if (idx > 0) list.add(new AbstractMap.SimpleEntry<>(
                line.substring(0,idx), line.substring(idx+1)));
        }
        return list;
    }
    private Set<String> defaultOrderInjectionParams() {
        return new LinkedHashSet<>(Arrays.asList(V5_DEFAULT_ORDER_INJECTION_PARAMS));
    }
    private List<Pattern> defaultNoisePatterns() {
        return Arrays.stream(V5_DEFAULT_NOISE_PATTERNS).map(Pattern::compile).collect(Collectors.toList());
    }
    private List<Pattern> defaultParamBlPatterns() {
        return Arrays.stream(V5_DEFAULT_PARAM_BLACKLIST).map(Pattern::compile).collect(Collectors.toList());
    }
    private List<Pattern> defaultUrlBlPatterns() {
        return Arrays.stream(V5_DEFAULT_URL_BLACKLIST).map(Pattern::compile).collect(Collectors.toList());
    }

    // --- V5 Default Error Patterns (102 patterns) ---
    private static final String[] V5_DEFAULT_ERROR_PATTERNS = {
        "(?i)Warning.*mysql_.*","(?i)You have an error in your SQL syntax","(?i)Microsoft SQL Server","(?i)ODBC SQL Server Driver","(?i)Unclosed quotation mark after the character string","(?i)Incorrect syntax near",
        "(?i)ORA-\\d{5}","(?i)PostgreSQL.*ERROR","(?i)org\\.postgresql\\.util\\.PSQLException","(?i)SQLite/JDBCDriver","(?i)SQLite.*error","SQL syntax.*?MySQL",
        "Unknown column","java.sql.SQLSyntaxErrorException","Error SQL:","Syntax error","附近有语法错误","(?i)java\\.sql\\.SQLException",
        "(?i)SQLSyntaxErrorException","引号不完整","System.Exception: SQL Execution Error!","com.mysql.jdbc","valid MySQL result","your MySQL server version",
        "MySqlClient","MySqlException","valid PostgreSQL result","PG::SyntaxError:","org.postgresql.jdbc","PSQLException",
        "Microsoft SQL Native Client error","SQLServer JDBC Driver","com.jnetdirect.jsql","macromedia.jdbc.sqlserver","com.microsoft.sqlserver.jdbc","Microsoft Access",
        "Access Database Engine","ODBC Microsoft Access","Oracle error","DB2 SQL error","Sybase message","SybSQLException",
        "System.Data.SqlClient.SqlException","Exception: ORDER BY","System.Exception: ORDER BY","Maticsoft.DBUtility","语法错误.{1,30}在查询表达式","ArgumentException.{1,5}列",
        "Error querying database","Illegal argument to a regular expression.","You have an error in your SQL syntax;","You have an error in your SQL syntax near","UPDATE .*? SET .*?","Unexpected end of command in statement",
        "import javax.swing.table.TableColumnModel;","System\\.Data\\.OleDb\\.OleDbException","Syntax error in string in query expression","Syntax error in query expression","SQLSTATE=\\d+","SELECT .*? FROM .*?",
        "PostgreSQL query failed:","pg_query\\(\\) \\[:","pg_exec\\(\\) \\[:","on MySQL result index","mysql_fetch_array\\(\\)","MySQL server version for the right syntax to use",
        "mssql_query\\(\\)","Microsoft OLE DB Provider for SQL Server","Microsoft OLE DB Provider for ODBC Drivers","Microsoft JET Database Engine","internal error \\[IBM\\]\\[CLI Driver\\]\\[DB2/6000\\]","INSERT INTO .*?",
        "has occurred in the vicinity of:","Dynamic SQL Error","ADODB.Recordset'","Column count doesn't match value count at row","Column count doesn't match","Procedure '[^']+' requires parameter '[^']+'",
        "Sybase message:","Table '[^']+' doesn't exist","the used select statements have different number of columns","Unclosed quotation mark before the character string","(PLS|ORA)-[0-9][0-9][0-9][0-9]","\\[CLI Driver\\]",
        "\\[DM_QUERY_E_SYNTAX\\]","\\[Macromedia\\]\\[SQLServer JDBC Driver\\]","\\[Microsoft\\]\\[ODBC Microsoft Access Driver\\]","\\[Microsoft\\]\\[ODBC SQL Server Driver\\]","\\[MySQL\\]\\[ODBC","\\[SQL Server\\]",
        "\\[SqlException","\\[SQLServer JDBC Driver\\]","<b>Warning</b>:  ibase_","A Parser Error \\(syntax error\\)","ADODB\\.Field \\(0x800A0BCD\\)<br>","An illegal character has been found in the statement",
        "com\\.informix\\.jdbc","Data type mismatch in criteria expression.","DB2 SQL error:","Dynamic Page Generation Error:","org.hibernate.QueryException:","\\(PLS|ORA\\)-[0-9][0-9][0-9][0-9]"
    };

    // --- V5 Default Append Params (113 entries) ---
    private static final String[] V5_DEFAULT_APPEND_PARAMS = {
        "orderType:orderType","columnsBy:columnsBy","has_column:has_column",
        "orderList:[{\"isAsc\": false,\"orderByColumn\":\"aaaa\"}]",
        "orderByColumn:orderByColumn","sortByNum:sortByNum","orderLimit:orderLimit",
        "sort_id:sort_id","sortField:sortField","sortBy:sortBy","columnIndex:columnIndex",
        "order:order","columnFirst:columnFirst","order_field:order_field","orderby:orderby",
        "sort_key:sort_key","columnType:columnType","columns_first:columns_first",
        "custom_columns:custom_columns","sort_field:sort_field","sortOrder:sortOrder",
        "columns_name:columns_name","columnKey:columnKey","startDate:startDate",
        "order_key:order_key","sortName:sortName","columns:columns","orderBy:orderBy",
        "columnsName:columnsName","column_first:column_first","columns_types:columns_types",
        "descList:descList","sort_no:sort_no","sortList:sortList","where:where",
        "hasColumns:hasColumns","orderDesc:orderDesc","orderName:orderName",
        "sort_types:sort_types","columnTypes:columnTypes","orderByColumns:orderByColumns",
        "column:column","is_orderby:is_orderby","customColumns:customColumns",
        "filter:filter","asc:asc","column_key:column_key","sortNo:sortNo",
        "sort_type:sort_type","is_asc:is_asc","sortColumn:sortColumn","sortByNumber:sortByNumber",
        "columns_by:columns_by","order_by:order_by","columnsComment:columnsComment",
        "columnName:columnName","sqlOrder:sqlOrder","columnsIndex:columnsIndex",
        "column_comment:column_comment","columnBy:columnBy","has_columns:has_columns",
        "order_type:order_type","columns_comment:columns_comment","orderKey:orderKey",
        "customColumn:customColumn","orderSort:orderSort","columnComment:columnComment",
        "sort:sort","sort_index:sort_index","order_index:order_index","column_index:column_index",
        "order_asc:order_asc","columns_key:columns_key","asc_sort:asc_sort",
        "sortKey:sortKey","sortColumns:sortColumns","orderTypes:orderTypes","ascSort:ascSort",
        "column_type:column_type","order_limit:order_limit","desc:desc",
        "hasColumn:hasColumn","isOrderBy:isOrderBy","sortIndex:sortIndex",
        "columns_type:columns_type","orderNum:orderNum","sortTypes:sortTypes",
        "sort_by:sort_by","sort_name:sort_name","columnsKey:columnsKey",
        "order_name:order_name","sql:sql","orderAsc:orderAsc","sort_column:sort_column",
        "sortId:sortId","columns_index:columns_index","desc_list:desc_list",
        "sort_list:sort_list","sort_order:sort_order","sqlOrderBy:sqlOrderBy",
        "sort_columns:sort_columns","orderBySort:orderBySort","columnsFirst:columnsFirst",
        "order_types:order_types","column_name:column_name","order_desc:order_desc",
        "column_types:column_types","sortType:sortType","outFields:outFields",
        "orderIndex:orderIndex","orderField:orderField","order_list:order_list",
        "custom_column:custom_column"
    };

    // --- V5 Default Order Injection Params (all append param keys) ---
    private static final String[] V5_DEFAULT_ORDER_INJECTION_PARAMS = {
        "orderType","columnsBy","has_column","orderList","orderByColumn","sortByNum",
        "orderLimit","sort_id","sortField","sortBy","columnIndex","order","columnFirst",
        "order_field","orderby","sort_key","columnType","columns_first","custom_columns",
        "sort_field","sortOrder","columns_name","columnKey","startDate","order_key",
        "sortName","columns","orderBy","columnsName","column_first","columns_types",
        "descList","sort_no","sortList","where","hasColumns","orderDesc","orderName",
        "sort_types","columnTypes","orderByColumns","column","is_orderby","customColumns",
        "filter","asc","column_key","sortNo","sort_type","is_asc","sortColumn",
        "sortByNumber","columns_by","order_by","columnsComment","columnName","sqlOrder",
        "columnsIndex","column_comment","columnBy","has_columns","order_type",
        "columns_comment","orderKey","customColumn","orderSort","columnComment","sort",
        "sort_index","order_index","column_index","order_asc","columns_key","asc_sort",
        "sortKey","sortColumns","orderTypes","ascSort","column_type","order_limit","desc",
        "hasColumn","isOrderBy","sortIndex","columns_type","orderNum","sortTypes",
        "sort_by","sort_name","columnsKey","order_name","sql","orderAsc","sort_column",
        "sortId","columns_index","desc_list","sort_list","sort_order","sqlOrderBy",
        "sort_columns","orderBySort","columnsFirst","order_types","column_name",
        "order_desc","column_types","sortType","outFields","orderIndex","orderField",
        "order_list","custom_column"
    };

    // --- V5 Default Noise Regex (14 patterns) ---
    private static final String[] V5_DEFAULT_NOISE_PATTERNS = {
        "\\b\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}.*?",
        "\"[a-zA-Z]+\":1[7-9]\\d{7,10}",
        "\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b",
        "\\b[0-9a-fA-F]{128}\\b","\\b[0-9a-fA-F]{64}\\b","\\b[0-9a-fA-F]{40}\\b","\\b[0-9a-fA-F]{32}\\b",
        "\\b1\\d{12}\\b","\\b1\\d{9}\\b",
        "\\b\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,6})?(?:Z|[+-]\\d{2}:\\d{2})?\\b",
        "\\beyJ[a-zA-Z0-9_-]{5,}\\.[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}\\b",
        "(?i)(token|access[_-]?token|refresh[_-]?token|id[_-]?token|jwt)\\s*[:=]\\s*[\"']?[A-Za-z0-9._+/=-]{8,}",
        "(?i)(sessionid|session_id|jsessionid|phpsessid)\\s*[:=]\\s*[\"']?[A-Za-z0-9._-]{6,}",
        "(?i)(traceId|requestId|reqId|nonce|csrf)\\s*[:=]\\s*[\"']?[^\"',&\\s]+",
        "(?i)\\bAuthorization\\b\\s*:\\s*\\bBearer\\b\\s+[A-Za-z0-9._+/=-]{8,}",
        "(?i)\\b(sessionid|session_id|JSESSIONID|PHPSESSID)=([^;,\\s\"]+)"
    };

    // --- V5 Default Param Blacklist (8 patterns) ---
    private static final String[] V5_DEFAULT_PARAM_BLACKLIST = {
        "(?i)^timestamp$","(?i)^time$",
        "(?i)^callback$","(?i)^_$","(?i)^csrf$","(?i)^token$","(?i)^sign$","(?i)^signature$"
    };

    // --- V5 Default URL Blacklist (124 patterns) ---
    private static final String[] V5_DEFAULT_URL_BLACKLIST = {
        "/static/.*",
        ".*\\.css$",".*\\.js$",".*\\.jpg$",".*\\.jpeg$",".*\\.png$",".*\\.gif$",".*\\.glb$",
        ".*\\.bmp$",".*\\.svg$",".*\\.ico$",".*\\.woff$",".*\\.woff2$",".*\\.ts$",
        ".*\\.m3u8$",".*\\.OTF$",".*\\.3g2$",".*\\.3gp$",".*\\.7z$",".*\\.aac$",
        ".*\\.abw$",".*\\.aif$",".*\\.aifc$",".*\\.aiff$",".*\\.apk$",".*\\.arc$",
        ".*\\.au$",".*\\.avi$",".*\\.azw$",".*\\.bat$",".*\\.bin$",".*\\.bmp$",
        ".*\\.bz$",".*\\.bz2$",".*\\.cmd$",".*\\.cmx$",".*\\.cod$",".*\\.csh$",
        ".*\\.css$",".*\\.csv$",".*\\.dll$",".*\\.doc$",".*\\.docx$",".*\\.ear$",
        ".*\\.eot$",".*\\.epub$",".*\\.exe$",".*\\.flac$",".*\\.flv$",".*\\.gif$",
        ".*\\.gz$",".*\\.ico$",".*\\.ics$",".*\\.ief$",".*\\.jar$",".*\\.jfif$",
        ".*\\.jpe$",".*\\.jpeg$",".*\\.jpg$",".*\\.less$",".*\\.m3u$",".*\\.mid$",
        ".*\\.midi$",".*\\.mjs$",".*\\.mkv$",".*\\.mov$",".*\\.mp2$",".*\\.mp3$",
        ".*\\.mp4$",".*\\.mpa$",".*\\.mpe$",".*\\.mpeg$",".*\\.mpg$",".*\\.mpkg$",
        ".*\\.mpp$",".*\\.mpv2$",".*\\.odp$",".*\\.ods$",".*\\.odt$",".*\\.oga$",
        ".*\\.ogg$",".*\\.ogv$",".*\\.ogx$",".*\\.otf$",".*\\.pbm$",".*\\.pdf$",
        ".*\\.pgm$",".*\\.png$",".*\\.pnm$",".*\\.ppm$",".*\\.ppt$",".*\\.pptx$",
        ".*\\.ra$",".*\\.ram$",".*\\.rar$",".*\\.ras$",".*\\.rgb$",".*\\.rmi$",
        ".*\\.rtf$",".*\\.scss$",".*\\.sh$",".*\\.snd$",".*\\.svg$",".*\\.swf$",
        ".*\\.tar$",".*\\.tif$",".*\\.tiff$",".*\\.ttf$",".*\\.vsd$",".*\\.war$",
        ".*\\.wav$",".*\\.weba$",".*\\.webm$",".*\\.webp$",".*\\.wmv$",".*\\.woff$",
        ".*\\.woff2$",".*\\.xbm$",".*\\.xls$",".*\\.xlsx$",".*\\.xpm$",".*\\.xul$",
        ".*\\.xwd$",".*\\.zip$",
    };

    // =========================================================================
    // Helpers
    // =========================================================================
    private Path path(String name) { return DIR.resolve(name); }
    private int ip(Properties p, String k, int d) { try { return Integer.parseInt(p.getProperty(k,""+d)); } catch(NumberFormatException e){return d;} }
    private boolean bp(Properties p, String k, boolean d) { String v=p.getProperty(k); return v==null?d:"true".equalsIgnoreCase(v.strip()); }
    private double dp(Properties p, String k, double d) { try { return Double.parseDouble(p.getProperty(k,""+d)); } catch(NumberFormatException e){return d;} }
    private String sp(Properties p, String k, String d) { String v = p.getProperty(k); return v != null ? v : d; }

    /** Decode \\xHH hex-escaped UTF-8 byte sequences to actual Unicode characters. */
    static String decodeHexEscapes(String s) {
        if (s == null || s.isEmpty()) return s;
        StringBuilder result = new StringBuilder();
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        int i = 0;
        while (i < s.length()) {
            if (i + 3 < s.length() && s.charAt(i) == '\\' && s.charAt(i + 1) == 'x') {
                try {
                    buf.write(Integer.parseInt(s.substring(i + 2, i + 4), 16));
                    i += 4;
                } catch (NumberFormatException e) {
                    flushHexBuf(buf, result);
                    result.append(s.charAt(i));
                    i++;
                }
            } else {
                flushHexBuf(buf, result);
                result.append(s.charAt(i));
                i++;
            }
        }
        flushHexBuf(buf, result);
        return result.toString();
    }

    private static void flushHexBuf(java.io.ByteArrayOutputStream buf, StringBuilder result) {
        if (buf.size() > 0) {
            result.append(new String(buf.toByteArray(), StandardCharsets.UTF_8));
            buf.reset();
        }
    }

    // =========================================================================
    // Getters / Setters
    // =========================================================================
    public int getThreadCount() { return threadCount; }
    public void setThreadCount(int v) { threadCount = v; }
    public int getMaxQueueSize() { return maxQueueSize; }
    public void setMaxQueueSize(int v) { maxQueueSize = v; }
    public boolean isDeduplicateTasks() { return deduplicateTasks; }
    public void setDeduplicateTasks(boolean v) { deduplicateTasks = v; }

    public boolean isEnableError() { return enableError; }
    public void setEnableError(boolean v) { enableError = v; }
    public boolean isEnableBoolean() { return enableBoolean; }
    public void setEnableBoolean(boolean v) { enableBoolean = v; }
    public boolean isEnableOrder() { return enableOrder; }
    public void setEnableOrder(boolean v) { enableOrder = v; }

    public boolean isEnableOrderInjection() { return enableOrderInjection; }
    public void setEnableOrderInjection(boolean v) { enableOrderInjection = v; }

    public boolean isEnableUrlEncodeChars() { return enableUrlEncodeChars; }
    public void setEnableUrlEncodeChars(boolean v) { enableUrlEncodeChars = v; }
    public String getUrlEncodeChars() { return urlEncodeChars; }
    public void setUrlEncodeChars(String v) { urlEncodeChars = v != null ? v : ""; }

    public boolean isMonitorProxy() { return monitorProxy; }
    public void setMonitorProxy(boolean v) { monitorProxy = v; }
    public boolean isMonitorRepeater() { return monitorRepeater; }
    public void setMonitorRepeater(boolean v) { monitorRepeater = v; }

    public boolean isEnableDomainWl() { return enableDomainWl; }
    public void setEnableDomainWl(boolean v) { enableDomainWl = v; }
    public boolean isEnableDomainBl() { return enableDomainBl; }
    public void setEnableDomainBl(boolean v) { enableDomainBl = v; }
    public boolean isEnableUrlBl() { return enableUrlBl; }
    public void setEnableUrlBl(boolean v) { enableUrlBl = v; }
    public boolean isEnableParamWl() { return enableParamWl; }
    public void setEnableParamWl(boolean v) { enableParamWl = v; }
    public boolean isEnableParamBl() { return enableParamBl; }
    public void setEnableParamBl(boolean v) { enableParamBl = v; }

    public boolean isEnableJsonValue() { return enableJsonValue; }
    public void setEnableJsonValue(boolean v) { enableJsonValue = v; }
    public boolean isEnableJsonInParam() { return enableJsonInParam; }
    public void setEnableJsonInParam(boolean v) { enableJsonInParam = v; }

    public double getSimilarityThreshold() { return similarityThreshold; }
    public void setSimilarityThreshold(double v) { similarityThreshold = v; }
    public double getLengthDiffRatio() { return lengthDiffRatio; }
    public void setLengthDiffRatio(double v) { lengthDiffRatio = v; }
    public int getLengthDiffAbs() { return lengthDiffAbs; }
    public void setLengthDiffAbs(int v) { lengthDiffAbs = v; }
    public boolean isRemoveWhitespace() { return removeWhitespace; }
    public void setRemoveWhitespace(boolean v) { removeWhitespace = v; }

    public boolean isEnableCustomErrorPocs() { return enableCustomErrorPocs; }
    public void setEnableCustomErrorPocs(boolean v) { enableCustomErrorPocs = v; }
    public boolean isBlockBuiltinQuotePocs() { return blockBuiltinQuotePocs; }
    public void setBlockBuiltinQuotePocs(boolean v) { blockBuiltinQuotePocs = v; }

    // --- Rule accessors ---
    public List<Pattern> getErrorPatterns() { return errorPatterns; }
    public List<Map.Entry<String,String>> getAppendParams() { return new ArrayList<>(appendParams); }
    public Map<String, Integer> getAppendParamGroups() { return new LinkedHashMap<>(appendParamGroups); }
    public Set<String> getOrderInjectionParams() { return new LinkedHashSet<>(orderInjectionParams); }
    public List<Pattern> getNoiseRegexes() { return noiseRegexes; }
    public List<Pattern> getNoisePatterns() { return noiseRegexes; } // alias
    public List<Pattern> getParamWhitelist() { return paramWhitelist; }
    public List<Pattern> getParamBlacklist() { return paramBlacklist; }
    public List<Pattern> getUrlBlacklist() { return urlBlacklist; }
    public List<String> getDomainWhitelist() { return domainWhitelist; }
    public List<String> getDomainBlacklist() { return domainBlacklist; }
    public List<Map.Entry<String,String>> getCustomHeaders() { return new ArrayList<>(customHeaders); }

    /** Load user-custom error POCs from SQL_error_pocs.ini, filtering out ', '', ''' */
    public List<String> getErrorPocs() {
        List<String> pocs = new ArrayList<>();
        Path f = path("SQL_error_pocs.ini");
        if (!Files.exists(f)) return pocs;
        try {
            for (String line : Files.readAllLines(f, StandardCharsets.UTF_8)) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                if (blockBuiltinQuotePocs) {
                    if (line.equals("'") || line.equals("''") || line.equals("'''")) continue;
                }
                pocs.add(line);
            }
        } catch (IOException e) { /* ignore */ }
        return pocs;
    }

    /** Force-reset all config files to built-in defaults. */
    public void resetAllConfigs() {
        ensureDir();
        saveSettings();
        savePatterns(path("SQL_diy_error.ini"), defaultErrorPatterns());
        saveAppendParamsToFile(defaultAppendParams());
        savePatterns(path("SQL_noise_regex.ini"), defaultNoisePatterns());
        savePatterns(path("SQL_param_blacklist.ini"), defaultParamBlPatterns());
        savePatterns(path("SQL_url_blacklist.ini"), defaultUrlBlPatterns());
        writeString(path("SQL_param_whitelist.ini"), "# One rule per line\n");
        writeString(path("SQL_domain_whitelist.ini"), "# One rule per line\n");
        writeString(path("SQL_domain_blacklist.ini"), "# One rule per line\n");
        writeString(path("SQL_append_params_groups.ini"), "# One rule per line\n");
        saveOrderInjectionParamsToFile(defaultOrderInjectionParams());
        writeString(path("SQL_error_pocs.ini"), "\\");
        writeString(path("SQL_custom_headers.ini"), "Range: bytes=0-1000");
        loadAll();
    }

    public Path getConfigDir() { return DIR; }
    public void loadAllConfigs() { loadAll(); }
}
