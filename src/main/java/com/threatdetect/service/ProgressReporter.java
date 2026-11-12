package com.threatdetect.service;

@FunctionalInterface
public interface ProgressReporter {
    void report(int percent);
}