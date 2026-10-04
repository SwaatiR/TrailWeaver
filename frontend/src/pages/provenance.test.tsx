import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { EvidenceProvenancePanel } from "./InvestigationDashboard";
import type {
  EvidenceProvenance,
  IncidentProvenance,
  ObservingRun,
} from "../types/api";

function run(overrides: Partial<ObservingRun> & { analysis_run_id: string }): ObservingRun {
  return {
    source_type: "local_file",
    source_label: "export.json",
    status: "completed",
    started_at: "2026-10-04T10:00:00.000000+00:00",
    finished_at: "2026-10-04T10:00:05.000000+00:00",
    ...overrides,
  };
}

function evidence(
  overrides: Partial<EvidenceProvenance> & { signal_id: string },
): EvidenceProvenance {
  return {
    rule_id: "aws.auth.console_login_without_mfa",
    title: "Console login without MFA",
    provider: "aws",
    event_id: "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
    event_time: "2026-09-23T10:00:00.000000+00:00",
    observation_state: "recorded",
    first_recorded_at: "2026-10-04T10:00:05.000000+00:00",
    observed_run_ids: ["run-1"],
    ...overrides,
  };
}

function provenance(overrides: Partial<IncidentProvenance>): IncidentProvenance {
  const observing = run({ analysis_run_id: "run-1" });
  return {
    incident_id: "incident-1",
    summary: {
      evidence_signal_count: 1,
      identified_event_count: 1,
      identified_events_with_recorded_observations: 1,
      unidentified_signal_count: 0,
      observing_run_count: 1,
      source_types: ["local_file"],
      event_time_start: "2026-09-23T10:00:00.000000+00:00",
      event_time_end: "2026-09-23T10:00:00.000000+00:00",
    },
    observing_runs: [observing],
    evidence: [evidence({ signal_id: "signal-1" })],
    ...overrides,
  };
}

describe("EvidenceProvenancePanel", () => {
  it("shows a local loading state", () => {
    render(<EvidenceProvenancePanel provenance={{ status: "loading" }} onRetry={() => {}} />);
    expect(screen.getByLabelText("Loading analysis")).toBeInTheDocument();
    expect(screen.getByText("Evidence provenance")).toBeInTheDocument();
  });

  it("shows a retryable error", () => {
    const onRetry = vi.fn();
    render(
      <EvidenceProvenancePanel
        provenance={{ status: "error", message: "boom" }}
        onRetry={onRetry}
      />,
    );
    expect(screen.getByText("Evidence provenance unavailable")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Retry"));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("summarizes single-run provenance without a database table", () => {
    const { container } = render(
      <EvidenceProvenancePanel
        provenance={{ status: "success", data: provenance({}) }}
        onRetry={() => {}}
      />,
    );
    expect(screen.getByText("Evidence signals")).toBeInTheDocument();
    expect(screen.getByText("Observing runs")).toBeInTheDocument();
    expect(screen.getAllByText("Event time")).toHaveLength(2);
    expect(screen.getByText("1 of 1")).toBeInTheDocument();
    expect(screen.getAllByText("Local File")).toHaveLength(2);
    expect(screen.getAllByText("export.json")).toHaveLength(2);
    expect(container.querySelector("table")).toBeNull();
  });

  it("summarizes multi-run provenance with repeated observations", () => {
    const data = provenance({
      observing_runs: [
        run({ analysis_run_id: "run-1", source_label: "a.json" }),
        run({ analysis_run_id: "run-2", source_label: "b.json" }),
      ],
      summary: {
        evidence_signal_count: 1,
        identified_event_count: 1,
        identified_events_with_recorded_observations: 1,
        unidentified_signal_count: 0,
        observing_run_count: 2,
        source_types: ["local_file"],
        event_time_start: "2026-09-23T10:00:00.000000+00:00",
        event_time_end: "2026-09-23T10:00:00.000000+00:00",
      },
      evidence: [
        evidence({ signal_id: "signal-1", observed_run_ids: ["run-1", "run-2"] }),
      ],
    });
    render(<EvidenceProvenancePanel provenance={{ status: "success", data }} onRetry={() => {}} />);
    expect(screen.getByText("Observed in 2 recorded runs.")).toBeInTheDocument();
    expect(screen.getByText("+1 additional observation")).toBeInTheDocument();
    // Expanded run records stay in the DOM for assistive technology.
    expect(screen.getByText("run-1")).toBeInTheDocument();
    expect(screen.getByText("run-2")).toBeInTheDocument();
  });

  it("explains partial history", () => {
    const data = provenance({
      summary: {
        evidence_signal_count: 3,
        identified_event_count: 3,
        identified_events_with_recorded_observations: 2,
        unidentified_signal_count: 0,
        observing_run_count: 1,
        source_types: ["local_file"],
        event_time_start: "2026-09-23T10:00:00.000000+00:00",
        event_time_end: "2026-09-23T10:10:00.000000+00:00",
      },
      evidence: [
        evidence({ signal_id: "signal-1" }),
        evidence({ signal_id: "signal-2", observation_state: "history_unavailable", first_recorded_at: null, observed_run_ids: [] }),
        evidence({ signal_id: "signal-3" }),
      ],
    });
    render(<EvidenceProvenancePanel provenance={{ status: "success", data }} onRetry={() => {}} />);
    expect(
      screen.getByText("Recorded run history is available for 2 of 3 identified events."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Recorded run history is unavailable for this evidence."),
    ).toBeInTheDocument();
  });

  it("explains evidence without a provider event ID", () => {
    const data = provenance({
      summary: {
        evidence_signal_count: 1,
        identified_event_count: 0,
        identified_events_with_recorded_observations: 0,
        unidentified_signal_count: 1,
        observing_run_count: 0,
        source_types: [],
        event_time_start: "2026-09-23T10:00:00.000000+00:00",
        event_time_end: "2026-09-23T10:00:00.000000+00:00",
      },
      observing_runs: [],
      evidence: [
        evidence({
          signal_id: "signal-1",
          event_id: null,
          observation_state: "identity_unavailable",
          first_recorded_at: null,
          observed_run_ids: [],
        }),
      ],
    });
    render(<EvidenceProvenancePanel provenance={{ status: "success", data }} onRetry={() => {}} />);
    expect(
      screen.getByText(
        "Run history is unavailable because this evidence has no provider event ID.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("No provider event ID")).toBeInTheDocument();
  });

  it("renders nullable source labels and long S3 labels truthfully", () => {
    const longLabel =
      "s3://example-bucket/logs/2026/10/04/very-long-cloudtrail-export-filename-that-keeps-going.json";
    const data = provenance({
      observing_runs: [
        run({ analysis_run_id: "run-1", source_type: "s3_object", source_label: longLabel }),
        run({ analysis_run_id: "run-2", source_label: null }),
      ],
      summary: {
        evidence_signal_count: 1,
        identified_event_count: 1,
        identified_events_with_recorded_observations: 1,
        unidentified_signal_count: 0,
        observing_run_count: 2,
        source_types: ["s3_object", "local_file"],
        event_time_start: "2026-09-23T10:00:00.000000+00:00",
        event_time_end: "2026-09-23T10:00:00.000000+00:00",
      },
      evidence: [
        evidence({ signal_id: "signal-1", observed_run_ids: ["run-1", "run-2"] }),
      ],
    });
    render(<EvidenceProvenancePanel provenance={{ status: "success", data }} onRetry={() => {}} />);
    // Compact labels truncate visually; the full persisted value stays available.
    expect(screen.queryByText(longLabel)).toBeInTheDocument();
    expect(screen.getAllByText("No source label")).toHaveLength(2);
    expect(screen.getAllByText("S3 Object")).toHaveLength(2);
  });

  it("shows the first-recorded fact even when run history is unavailable", () => {
    const data = provenance({
      summary: {
        evidence_signal_count: 1,
        identified_event_count: 1,
        identified_events_with_recorded_observations: 0,
        unidentified_signal_count: 0,
        observing_run_count: 0,
        source_types: [],
        event_time_start: "2026-09-23T10:00:00.000000+00:00",
        event_time_end: "2026-09-23T10:00:00.000000+00:00",
      },
      observing_runs: [],
      evidence: [
        evidence({
          signal_id: "signal-1",
          observation_state: "history_unavailable",
          first_recorded_at: "2026-10-04T10:00:05.000000+00:00",
          observed_run_ids: [],
        }),
      ],
    });
    render(<EvidenceProvenancePanel provenance={{ status: "success", data }} onRetry={() => {}} />);
    // Intentional: the first-recorded fact survives while run history is
    // reported unavailable. Neither implies an originating run.
    expect(screen.getByText("First recorded by TrailWeaver")).toBeInTheDocument();
    expect(
      screen.getByText("Recorded run history is unavailable for this evidence."),
    ).toBeInTheDocument();
  });

  it("exposes run status as text, never color alone", () => {
    const data = provenance({
      observing_runs: [
        run({ analysis_run_id: "run-1", status: "running", finished_at: null }),
        run({ analysis_run_id: "run-2", status: "failed" }),
      ],
      evidence: [
        evidence({ signal_id: "signal-1", observed_run_ids: ["run-1", "run-2"] }),
      ],
    });
    render(<EvidenceProvenancePanel provenance={{ status: "success", data }} onRetry={() => {}} />);
    expect(screen.getByText("Running")).toBeInTheDocument();
    expect(screen.getByText("Failed")).toBeInTheDocument();
    expect(screen.getByText("Still running")).toBeInTheDocument();
  });

  it("never shows stale props after the selection changes", () => {
    const first = provenance({ incident_id: "incident-1" });
    const second = provenance({
      incident_id: "incident-2",
      observing_runs: [run({ analysis_run_id: "run-9", source_label: "other.json" })],
      evidence: [evidence({ signal_id: "signal-9", observed_run_ids: ["run-9"] })],
    });
    const { rerender } = render(
      <EvidenceProvenancePanel provenance={{ status: "success", data: first }} onRetry={() => {}} />,
    );
    expect(screen.getAllByText("export.json")).toHaveLength(2);
    rerender(
      <EvidenceProvenancePanel provenance={{ status: "success", data: second }} onRetry={() => {}} />,
    );
    expect(screen.queryAllByText("export.json")).toHaveLength(0);
    expect(screen.getAllByText("other.json")).toHaveLength(2);
    expect(screen.getByText("run-9")).toBeInTheDocument();
  });
});
