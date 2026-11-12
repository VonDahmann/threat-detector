package com.threatdetect.service;

import com.threatdetect.model.InputItem;

import java.util.List;

/** Valid rows become items; invalid rows are reported, never thrown. */
public record CsvParseResult(List<InputItem> items, List<RowError> errors, int totalRows) {}