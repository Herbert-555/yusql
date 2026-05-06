package com.yusql.model;

public class TestPoint {
    private final String paramName;
    private final String paramValue;
    private final ParamType paramType;
    private final String jsonPath;
    private final JsonTestType jsonTestType;
    private final boolean jsonEncoded;

    public TestPoint(String paramName, String paramValue, ParamType paramType,
                     String jsonPath, JsonTestType jsonTestType, boolean jsonEncoded) {
        this.paramName = paramName;
        this.paramValue = paramValue;
        this.paramType = paramType;
        this.jsonPath = jsonPath != null ? jsonPath : "";
        this.jsonTestType = jsonTestType != null ? jsonTestType : JsonTestType.NONE;
        this.jsonEncoded = jsonEncoded;
    }

    public String getParamName() { return paramName; }
    public String getParamValue() { return paramValue; }
    public ParamType getParamType() { return paramType; }
    public String getJsonPath() { return jsonPath; }
    public JsonTestType getJsonTestType() { return jsonTestType; }
    public boolean isJsonEncoded() { return jsonEncoded; }

    /** Combined display name for the "参数" column */
    public String displayPath() {
        if (jsonTestType == JsonTestType.NONE) return paramName;
        // Outer param with JSON value: no (json) prefix
        if (jsonPath == null || jsonPath.isEmpty() || jsonPath.equals("$")) return paramName;
        // Inner JSON key: strip $. prefix, show (json) keypath
        String inner = jsonPath.startsWith("$.") ? jsonPath.substring(2) : jsonPath;
        return "(json) " + inner;
    }

    public String dedupKey() {
        return paramName + "|" + paramType + "|" + jsonPath + "|" + jsonTestType;
    }
}
