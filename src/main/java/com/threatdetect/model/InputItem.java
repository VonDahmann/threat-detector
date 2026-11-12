package com.threatdetect.model;

import java.util.concurrent.atomic.AtomicInteger;

public final class InputItem {
    private static final AtomicInteger COUNTER = new AtomicInteger(1);

    private final int id;
    private final InputType type;
    private final String content;

    public InputItem(InputType type, String content) {
        this.id = COUNTER.getAndIncrement();
        this.type = type;
        this.content = content;
    }

    public int getId() { return id; }
    public InputType getType() { return type; }
    public String getContent() { return content; }
}