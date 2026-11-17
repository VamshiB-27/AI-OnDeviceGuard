package com.vcs.ondeviceguard.model;

public final class NetworkFlowResult {

    private final String label;
    private final double decisionScore;
    private final double attackProbability;

    public NetworkFlowResult(
            String label,
            double decisionScore,
            double attackProbability) {

        this.label = label;
        this.decisionScore = decisionScore;
        this.attackProbability = attackProbability;
    }

    public String getLabel() {
        return label;
    }

    public double getDecisionScore() {
        return decisionScore;
    }

    public double getAttackProbability() {
        return attackProbability;
    }

    public boolean isAttack() {
        return "ATTACK".equals(label);
    }
}