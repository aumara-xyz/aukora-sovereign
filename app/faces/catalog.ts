// SPDX-License-Identifier: AGPL-3.0-or-later

export interface FaceManifest {
  readonly id: string;
  readonly title: string;
  readonly organ: string;
  readonly requires: readonly string[];
  readonly menu: { readonly section: "workspace" | "aukora_apps" | "system"; readonly order: number };
  readonly surface: string;
  readonly wasm?: boolean;
  readonly capabilities: Readonly<Record<string, { readonly methods: readonly string[]; readonly topics: readonly string[] }>>;
}

export const FACE_CATALOG: readonly FaceManifest[] = [
  {
    "id": "threads",
    "title": "Threads",
    "organ": "body",
    "requires": [
      "body"
    ],
    "menu": {
      "section": "workspace",
      "order": 0
    },
    "surface": "./faces/threads/index.html",
    "capabilities": {
      "body": {
        "methods": [
          "session.create",
          "session.open",
          "session.list",
          "chat.turn",
          "model.cancel"
        ],
        "topics": [
          "session.event"
        ]
      }
    }
  },
  {
    "id": "sidebar",
    "title": "Sidebar",
    "organ": "body",
    "requires": [
      "body"
    ],
    "menu": {
      "section": "workspace",
      "order": 1
    },
    "surface": "./faces/sidebar/index.html",
    "capabilities": {
      "body": {
        "methods": [
          "session.list",
          "session.open"
        ],
        "topics": [
          "session.event"
        ]
      }
    }
  },
  {
    "id": "lingwa",
    "title": "Auma Lingwa",
    "organ": "body",
    "requires": [
      "body"
    ],
    "menu": {
      "section": "aukora_apps",
      "order": 2
    },
    "surface": "./faces/lingwa/index.html",
    "capabilities": {
      "body": {
        "methods": [],
        "topics": []
      }
    }
  },
  {
    "id": "live",
    "title": "Auma Live",
    "organ": "body",
    "requires": [
      "body"
    ],
    "menu": {
      "section": "aukora_apps",
      "order": 3
    },
    "surface": "./faces/live/index.html",
    "capabilities": {
      "body": {
        "methods": [],
        "topics": []
      }
    }
  },
  {
    "id": "zetaharp",
    "title": "Zeta Harp",
    "organ": "body",
    "requires": [
      "body"
    ],
    "menu": {
      "section": "aukora_apps",
      "order": 4
    },
    "surface": "./faces/zetaharp/index.html",
    "capabilities": {
      "body": {
        "methods": [],
        "topics": []
      }
    }
  },
  {
    "id": "humangraph",
    "title": "Human Graph",
    "organ": "network",
    "requires": [
      "network"
    ],
    "menu": {
      "section": "aukora_apps",
      "order": 5
    },
    "surface": "./faces/humangraph/index.html",
    "capabilities": {
      "network": {
        "methods": [
          "contacts.list"
        ],
        "topics": []
      }
    }
  },
  {
    "id": "media",
    "title": "Media",
    "organ": "body",
    "requires": [
      "body"
    ],
    "menu": {
      "section": "aukora_apps",
      "order": 6
    },
    "surface": "./faces/media/index.html",
    "capabilities": {
      "body": {
        "methods": [],
        "topics": []
      }
    }
  },
  {
    "id": "memory",
    "title": "Memory",
    "organ": "kira",
    "requires": [
      "kira"
    ],
    "menu": {
      "section": "aukora_apps",
      "order": 7
    },
    "surface": "./faces/memory/index.html",
    "capabilities": {
      "kira": {
        "methods": [
          "memory.list",
          "memory.recall"
        ],
        "topics": []
      }
    }
  },
  {
    "id": "messages",
    "title": "Messages",
    "organ": "network",
    "requires": [
      "network"
    ],
    "menu": {
      "section": "aukora_apps",
      "order": 8
    },
    "surface": "./faces/messages/index.html",
    "capabilities": {
      "network": {
        "methods": [
          "contacts.list",
          "messages.list",
          "refusals.counts"
        ],
        "topics": []
      }
    }
  },
  {
    "id": "documents",
    "title": "Documents",
    "organ": "kira",
    "requires": [
      "kira"
    ],
    "menu": {
      "section": "aukora_apps",
      "order": 9
    },
    "surface": "./faces/documents/index.html",
    "capabilities": {
      "kira": {
        "methods": [
          "documents.list",
          "documents.read"
        ],
        "topics": []
      }
    }
  },
  {
    "id": "aumlok",
    "title": "AUMLOK",
    "organ": "aumlok",
    "requires": [
      "aumlok"
    ],
    "menu": {
      "section": "system",
      "order": 10
    },
    "surface": "./faces/aumlok/index.html",
    "capabilities": {
      "aumlok": {
        "methods": [
          "status"
        ],
        "topics": []
      }
    }
  },
  {
    "id": "identity",
    "title": "Identity",
    "organ": "aumlok",
    "requires": [
      "aumlok"
    ],
    "menu": {
      "section": "system",
      "order": 11
    },
    "surface": "./faces/identity/index.html",
    "capabilities": {
      "aumlok": {
        "methods": [
          "identity"
        ],
        "topics": []
      }
    }
  },
  {
    "id": "coherence",
    "title": "Aura Coherence",
    "organ": "gate-aura",
    "requires": [
      "gate-aura",
      "body"
    ],
    "menu": {
      "section": "system",
      "order": 12
    },
    "surface": "./faces/coherence/index.html",
    "wasm": true,
    "capabilities": {
      "gate-aura": {
        "methods": [
          "head"
        ],
        "topics": [
          "head"
        ]
      },
      "body": {
        "methods": [
          "health.snapshot"
        ],
        "topics": [
          "health.snapshot"
        ]
      }
    }
  },
  {
    "id": "general",
    "title": "General",
    "organ": "body",
    "requires": [
      "body"
    ],
    "menu": {
      "section": "system",
      "order": 13
    },
    "surface": "./faces/general/index.html",
    "capabilities": {
      "body": {
        "methods": [
          "settings.general"
        ],
        "topics": []
      }
    }
  },
  {
    "id": "models",
    "title": "Models",
    "organ": "broker",
    "requires": [
      "broker"
    ],
    "menu": {
      "section": "system",
      "order": 14
    },
    "surface": "./faces/models/index.html",
    "capabilities": {
      "broker": {
        "methods": [
          "model.report"
        ],
        "topics": []
      }
    }
  },
  {
    "id": "plugins",
    "title": "Plugins",
    "organ": "body",
    "requires": [
      "body"
    ],
    "menu": {
      "section": "system",
      "order": 15
    },
    "surface": "./faces/plugins/index.html",
    "capabilities": {
      "body": {
        "methods": [
          "settings.plugins"
        ],
        "topics": []
      }
    }
  },
  {
    "id": "presets",
    "title": "Agent presets",
    "organ": "body",
    "requires": [
      "body"
    ],
    "menu": {
      "section": "system",
      "order": 16
    },
    "surface": "./faces/presets/index.html",
    "capabilities": {
      "body": {
        "methods": [
          "settings.presets"
        ],
        "topics": []
      }
    }
  },
  {
    "id": "archived",
    "title": "Archived sessions",
    "organ": "body",
    "requires": [
      "body"
    ],
    "menu": {
      "section": "system",
      "order": 17
    },
    "surface": "./faces/archived/index.html",
    "capabilities": {
      "body": {
        "methods": [
          "session.list",
          "session.open"
        ],
        "topics": [
          "session.event"
        ]
      }
    }
  }
];
