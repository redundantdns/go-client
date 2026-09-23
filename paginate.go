package redundantdns

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
)

// PageFetcher fetches one page of a list. The /v1 list routes answer the
// whole collection today (the alert history takes a limit, capped at 500),
// so a fetcher returns everything in one page; the iterator API stays the
// same if the server adds cursors later.
type PageFetcher[T any] func(ctx context.Context) ([]T, error)

// Paginate turns a fetcher into an iterator that yields every item, then
// stops; a fetch error is yielded once with the zero item.
//
//	for zone, err := range client.Zones.All(ctx) {
//		if err != nil { return err }
//		fmt.Println(zone.Name)
//	}
func Paginate[T any](ctx context.Context, fetch PageFetcher[T]) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		items, err := fetch(ctx)
		if err != nil {
			var zero T
			yield(zero, err)
			return
		}
		for _, item := range items {
			if !yield(item, nil) {
				return
			}
		}
	}
}

// Collect drains an iterator into a slice, stopping at the first error.
func Collect[T any](sequence iter.Seq2[T, error]) ([]T, error) {
	var items []T
	for item, err := range sequence {
		if err != nil {
			return items, err
		}
		items = append(items, item)
	}
	return items, nil
}

// Chunk splits items into pages of at most size items (size <= 0 = one
// page). Useful to render or process long lists in batches.
func Chunk[T any](items []T, size int) iter.Seq[[]T] {
	return func(yield func([]T) bool) {
		if size <= 0 {
			size = len(items)
		}
		for start := 0; start < len(items); start += size {
			end := min(start+size, len(items))
			if !yield(items[start:end]) {
				return
			}
		}
	}
}

// decodeJSON decodes a JSON body with a contextual error.
func decodeJSON(body []byte, out any) error {
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
