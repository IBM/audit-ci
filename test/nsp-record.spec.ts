import { describe, expect, it } from "vitest";
import {
  getAllowlistId,
  getNSPContent,
  isNSPRecordActive,
} from "../lib/nsp-record.js";

describe("getAllowlistId", () => {
  it("should get the allowlist id", () => {
    const id = getAllowlistId({
      myid: {
        active: true,
      },
    });
    expect(id).to.eql("myid");
  });
});

describe("getNSPContent", () => {
  it("should get the content", () => {
    const content = getNSPContent({
      myid: {
        active: true,
        notes: "my notes",
      },
    });

    expect(content).to.eql({
      active: true,
      notes: "my notes",
    });
  });
});

describe("isNSPRecordActive", () => {
  const now = new Date("November 15, 2022 11:00:00");

  it("should be active if active=true", () => {
    const active = isNSPRecordActive({
      myid: {
        active: true,
      },
    });

    expect(active).to.eql(true);
  });

  it("should not be active if active=false and there is no expiry", () => {
    const active = isNSPRecordActive({
      myid: {
        active: false,
      },
    });

    expect(active).to.eql(false);
  });

  it("should be active if expiry is in the future", () => {
    const active = isNSPRecordActive(
      {
        myid: {
          active: true,
          expiry: "November 20, 2022 11:00:00",
        },
      },
      now,
    );

    expect(active).to.eql(true);
  });

  it("should not be active if expiry is in the past", () => {
    const active = isNSPRecordActive(
      {
        myid: {
          active: true,
          expiry: "November 10, 2022 11:00:00",
        },
      },
      now,
    );

    expect(active).to.eql(false);
  });

  it("should not be active if expiry date is invalid", () => {
    const active = isNSPRecordActive(
      {
        myid: {
          active: true,
          expiry: "INVALID",
        },
      },
      now,
    );

    expect(active).to.eql(false);
  });

  it("should test some different date formats", () => {
    // These are variations of Nov 20, 2022.
    const activeDates = [
      "2022-11-20",
      "2022/11/20",
      "11/20/2022, 11:00:00",
      "20 November 2022 11:00",
      "20 November 2022 11:00 am",
      "2022-11-20T11:00:00.000-08:00",
      "Sun, 20 Nov 2022 11:00:00 PST",
      // eslint-disable-next-line unicorn/numeric-separators-style
      1668970800000,
    ];
    // These are variations of Nov 10, 2022.
    const expiredDates = [
      "2022-11-10",
      "2022/11/10",
      "11/10/2022, 11:00:00",
      "10 November 2022 11:00",
      "10 November 2022 11:00 am",
      "2022-11-10T11:00:00.000-08:00",
      "Thu, 10 Nov 2022 11:00:00 PST",
      // eslint-disable-next-line unicorn/numeric-separators-style
      1668106800000,
    ];

    for (const expiry of activeDates) {
      expect(
        isNSPRecordActive(
          {
            myid: {
              active: true,
              expiry,
            },
          },
          now,
        ),
      ).to.eql(true);
    }

    for (const expiry of expiredDates) {
      expect(
        isNSPRecordActive(
          {
            myid: {
              active: true,
              expiry,
            },
          },
          now,
        ),
      ).to.eql(false);
    }
  });
});
