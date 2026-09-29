// Small string/time helpers shared by core and UI.
#pragma once
#include <cstdint>
#include <ctime>
#include <string>
#include <string_view>
#include <vector>

namespace s3v {

std::string trim(std::string_view s);
std::vector<std::string> split(std::string_view s, char sep);
bool starts_with(std::string_view s, std::string_view p);
bool ends_with(std::string_view s, std::string_view p);
std::string to_lower(std::string_view s);

// RFC 3986 encoding as SigV4 wants it; '/' kept when encode_slash is false.
std::string uri_encode(std::string_view s, bool encode_slash);

// "2026-09-29T05:42:55.484Z" (S3 LastModified) → Unix seconds; 0 on failure.
int64_t parse_iso8601(std::string_view s);
// Local time "2026-09-29 13:42".
std::string format_local_time(int64_t unix_s);
// "20260929T054255Z"
std::string format_utc_compact(int64_t unix_s);
// "1.4 MB"
std::string human_size(uint64_t n);

// Path helpers on '/'-separated strings.
std::string path_join(std::string_view a, std::string_view b);
std::string path_dirname(std::string_view p);   // "" for top-level
std::string path_basename(std::string_view p);
std::string path_ext_lower(std::string_view p);  // "pdf" (no dot), "" if none

}  // namespace s3v
