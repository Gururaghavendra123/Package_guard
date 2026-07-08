"""Pydantic request/response models for the API (also documents the JSON the HUD consumes)."""

from __future__ import annotations

from pydantic import BaseModel


class CheckRequest(BaseModel):
    package: str  # 'name' or 'name@version'


class FeatureOut(BaseModel):
    key: str
    label: str
    value: float
    contribution: float
    detail: str


class SignalOut(BaseModel):
    level: str
    text: str
    feature: str


class CheckResponse(BaseModel):
    name: str
    version: str
    ecosystem: str
    score: float
    verdict: str
    level: str
    xgboost_score: float
    graph_score: float | None
    source: str
    features: list[FeatureOut]
    signals: list[SignalOut]
    graph: dict | None
    note: str | None = None
