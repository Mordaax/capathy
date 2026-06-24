"""Worker entry points for installed analysis tools; never executes input samples."""

import argparse
import json
import sys

from capathy.evidence import collect_features, read_sample


def main(argv=None):
    import capa.main
    from capa.features.extractors.base_extractor import StaticFeatureExtractor

    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["export-features"])
    capa.main.install_common_args(parser, wanted={"input_file", "format", "os", "signatures", "backend"})
    args = parser.parse_args(argv)
    try:
        capa.main.handle_common_args(args)
        capa.main.ensure_input_exists_from_cli(args)
        raw = read_sample(args.input_file)
        input_format = capa.main.get_input_format_from_cli(args)
        backend = capa.main.get_backend_from_cli(args, input_format)
        extractor = capa.main.get_extractor_from_cli(args, input_format, backend)
        if not isinstance(extractor, StaticFeatureExtractor):
            raise ValueError("complete export currently requires a static extractor")  # noqa: TRY004
        document = collect_features(extractor, input_format, len(raw))
        encoded = json.dumps(document, ensure_ascii=True)
        if len(encoded) > 32 << 20:
            raise ValueError("feature export exceeds 32 MiB")
        print(encoded)
        return 0
    except capa.main.ShouldExitError as error:
        return error.status_code
    except (ValueError, OSError) as error:
        print(f"capathy worker: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
