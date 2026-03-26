import React from "react";

export default function PaginationCenter({ page, totalPages, onPrev, onNext }) {
  return (
    <div className="px-5 py-3 border-t border-gray-800 flex items-center justify-center gap-3">
      <button
        onClick={onPrev}
        disabled={page <= 1}
        className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-1.5 text-gray-200 disabled:opacity-40"
      >
        ‹
      </button>

      <div className="text-gray-300 text-sm">
        <span className="font-semibold text-white">{page}</span>
        <span className="opacity-70"> of </span>
        <span className="font-semibold text-white">{totalPages}</span>
      </div>

      <button
        onClick={onNext}
        disabled={page >= totalPages}
        className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-1.5 text-gray-200 disabled:opacity-40"
      >
        ›
      </button>
    </div>
  );
}