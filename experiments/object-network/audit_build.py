"""Independent archived build audit; imports no builder, controller or product code."""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


def require(condition,message):
    if not condition:raise ValueError(message)


def equal(left,right,message):
    require(json.dumps(left,sort_keys=True,ensure_ascii=False,allow_nan=False)==
            json.dumps(right,sort_keys=True,ensure_ascii=False,allow_nan=False),message)


def parse(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,"duplicate original JSON key")
            value[key]=item
        return value
    def invalid(value):raise ValueError("nonfinite original JSON value: "+value)
    return json.loads(raw,object_pairs_hook=unique,parse_constant=invalid)


def sha256_text(value):
    require(isinstance(value,str) and re.fullmatch(r"[0-9a-f]{64}",value),"invalid SHA-256 digest")
    return value


def only(values,message):
    require(len(values)==1,message)
    return values[0]


class OwnedChildren:
    """Unique owned child incarnations and physically possible PID lifetimes."""
    def __init__(self):
        self.incarnations=set()
        self.lifetimes=defaultdict(list)

    def register(self,identity,end):
        require(identity.get("pid_source")=="owned_Popen_child","process identity is not an owned child")
        pid,start=identity["pid"],identity["spawn_monotonic_ns"]
        require(type(pid) is int and pid>0 and type(start) is int and start>0 and type(end) is int and end>start,
                "invalid owned process lifetime")
        require((pid,start) not in self.incarnations,"one child incarnation impersonates multiple processes")
        require(all(end<=lower or upper<=start for lower,upper in self.lifetimes[pid]),
                "one child PID claims overlapping independent lifetimes")
        self.incarnations.add((pid,start))
        self.lifetimes[pid].append((start,end))


def source_inventory(root,profile):
    """Independent exact input inventory; does not import the build controller."""
    paths={root/name for name in ("Cargo.toml","Cargo.lock","rust-toolchain.toml")}
    if profile=="network":
        for path in (root/"crates").rglob("*"):
            if path.is_file() and (path.suffix==".rs" or path.name=="Cargo.toml"):paths.add(path)
        for directory in ("object-network","object-capacity"):
            for path in (root/"experiments"/directory).rglob("*"):
                if path.is_file() and (path.suffix in (".rs",".py") or path.name in ("Cargo.toml","Cargo.lock")):
                    paths.add(path)
        return {path.relative_to(root).as_posix():file_digest(path) for path in sorted(paths)}
    for directory in ("crates","sdk/node","sdk/node-codec","experiments/object-service","experiments/object-network"):
        for path in (root/directory).rglob("*"):
            if path.is_file() and (path.suffix in (".rs",".py",".js",".mjs",".ts") or
                                   path.name in ("Cargo.toml","Cargo.lock","package.json")):
                paths.add(path)
    return {path.relative_to(root).as_posix():file_digest(path) for path in sorted(paths)}


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()


def receipt(directory, required=True, *, profile, require_artifacts=True, source_root=None):
    require(profile in ("network","service"),"unknown build evidence profile")
    directory=Path(directory)
    path=directory/"build-receipt.json"
    if not path.exists():
        require(not required,"missing frozen release build receipt")
        return {"status":"NOT_PROVIDED","diagnostic":True}
    value=parse(path.read_bytes())
    require(type(value.get("schema")) is int and value["schema"]==1 and value.get("status")=="passed" and
            value.get("profile")=="release",
            "invalid frozen release build receipt")
    require(type(value.get("exit_code")) is int and value["exit_code"]==0,"original Cargo process did not exit successfully")
    if profile=="service":
        target_name="scapd"
        target_manifest="crates/scap-service/Cargo.toml"
        command=["cargo","+1.90.0","build","--release","--locked","-p","scap-service",
                 "--bin","scapd","--message-format=json-render-diagnostics"]
        require(value.get("node")=="v22.16.0","wrong original Node runtime")
        rustc=value["rustc"]
        log_keys=("cargo.stdout.jsonl_sha256","cargo.stderr.log_sha256")
    else:
        target_name="scap-object-network"
        target_manifest="experiments/object-network/Cargo.toml"
        command=["cargo","+1.90.0","build","--release","--locked","--manifest-path",
                 target_manifest,"--message-format=json-render-diagnostics"]
        versions=value["versions"]
        require(isinstance(versions,dict) and set(versions)=={"rustc","cargo","cc"},"missing original compiler identities")
        rustc=versions["rustc"]
        require(isinstance(versions["cargo"],str) and versions["cargo"].startswith("cargo 1.90.0 "),"wrong original Cargo compiler")
        require(isinstance(versions["cc"],str) and versions["cc"].strip(),"missing native C compiler identity")
        log_keys=("build_stdout_sha256","build_stderr_sha256")
    equal(value["command"],command,"unpinned release Cargo command")
    require(isinstance(rustc,str) and rustc.startswith("rustc 1.90.0 (1159e78c4 2025-09-14)\n") and
            "release: 1.90.0" in rustc.splitlines(),"wrong original Rust compiler")
    require(isinstance(value["source_commit"],str) and re.fullmatch(r"[0-9a-f]{40}",value["source_commit"]),"invalid source commit")
    inputs=value["inputs"]
    require(isinstance(inputs,dict) and inputs,"missing original source manifest")
    for name,digest in inputs.items():
        safe=PurePosixPath(name)
        require(isinstance(name,str) and name==safe.as_posix() and not safe.is_absolute() and ".." not in safe.parts,
                "source manifest path escaped archive")
        sha256_text(digest)
    require({"Cargo.toml","Cargo.lock","rust-toolchain.toml"}<=set(inputs),"source manifest omitted locked build inputs")
    if profile=="network":
        require(hashlib.sha256(json.dumps(inputs,sort_keys=True,separators=(",",":")).encode()).hexdigest()==sha256_text(value["input_sha256"]),
                "original source manifest digest changed")
    evidence=value["archived_evidence"]
    equal({key:evidence[key] for key in ("schema","source_manifest","source_archive","cargo_stdout","cargo_stderr")},
          {"schema":1,"source_manifest":"build-source-manifest.json","source_archive":"build-source.tar",
           "cargo_stdout":"build-cargo.stdout.jsonl","cargo_stderr":"build-cargo.stderr.log"},"build archive paths changed")
    for key in ("source_manifest","source_archive"):
        require(file_digest(directory/evidence[key])==sha256_text(evidence[key+"_sha256"]),"archived build witness digest changed")
    manifest=parse((directory/evidence["source_manifest"]).read_bytes())
    equal(manifest,{"schema":1,"source_commit":value["source_commit"],"inputs":inputs},"source manifest differs from original receipt")
    source_bytes=0
    with tarfile.open(directory/evidence["source_archive"],mode="r:") as archive:
        members=archive.getmembers()
        require(len(members)==len(inputs) and {member.name for member in members}==set(inputs),"archived source inventory changed")
        for member in members:
            require(member.isfile() and 0<=member.size<=16*1024*1024,"source archive contains nonregular/oversized entry")
            stream=archive.extractfile(member)
            require(stream is not None,"source archive has no complete member bytes")
            with stream:
                raw=stream.read()
            require(len(raw)==member.size and hashlib.sha256(raw).hexdigest()==inputs[member.name],"archived original source bytes changed")
            source_bytes+=len(raw)
    for key,original in zip(("cargo_stdout","cargo_stderr"),log_keys):
        require(file_digest(directory/evidence[key])==sha256_text(value[original]),"original raw Cargo output changed")
    raw=(directory/evidence["cargo_stdout"]).read_bytes()
    require(raw and raw.endswith(b"\n"),"incomplete original Cargo JSONL")
    events=[parse(line) for line in raw.splitlines()]
    require(all(isinstance(event,dict) for event in events),"invalid original Cargo event")
    finished=[event for event in events if event.get("reason")=="build-finished"]
    require(len(finished)==1 and finished[0] is events[-1] and finished[0].get("success") is True,
            "missing unique final successful Cargo build-finished")
    binaries=[event for event in events if event.get("reason")=="compiler-artifact" and event.get("executable") is not None]
    binary_event=only(binaries,"missing/ambiguous original release binary")
    require(binary_event.get("target",{}).get("name")==target_name and binary_event["target"].get("kind")==["bin"],"Cargo built another executable target")
    compilation_source=PurePosixPath(value["source_root"])
    require(compilation_source.is_absolute() and ".." not in compilation_source.parts,"invalid original compiler source directory")
    require(binary_event["manifest_path"]==str(compilation_source/target_manifest) and target_manifest in inputs,
            "Cargo compiled another source manifest")
    target_source=PurePosixPath(target_manifest).parent/"src"/"main.rs"
    require(binary_event["target"]["src_path"]==str(compilation_source/target_source) and str(target_source) in inputs,
            "Cargo compiled another executable source")
    equal(binary_event["profile"],{"opt_level":"3","debuginfo":0,"debug_assertions":False,"overflow_checks":False,"test":False},
          "Cargo artifact is not the frozen uninstrumented release profile")
    binary=value["binary"]
    require(set(binary)=={"path","sha256"},"binary provenance fields changed")
    binary_path=PurePosixPath(binary["path"])
    require(binary_path.is_absolute() and ".." not in binary_path.parts and binary_path.name==target_name and
            binary_path.parent.name=="release" and binary_event["executable"]==str(binary_path),"binary is not the original release artifact")
    equal(binary_event["filenames"],[str(binary_path)],"Cargo linked another executable filename")
    sha256_text(binary["sha256"])
    native_events=[event for event in events if event.get("reason")=="build-script-executed" and
                   event.get("package_id","").rsplit("#",1)[-1].split("@",1)[0]=="libsql-ffi"]
    native=only(native_events,"missing/ambiguous original native libSQL build")
    native_path=PurePosixPath(native["out_dir"])
    require(native_path.is_absolute() and ".." not in native_path.parts and native_path.name=="out" and
            native_path.parent.name.startswith("libsql-ffi-") and native_path.parent.parent==binary_path.parent/"build",
            "native Cargo artifact escaped original release target")
    equal(native["linked_libs"],["static=libsql"],"Cargo did not statically link the original libSQL archive")
    equal(native["linked_paths"],["native="+str(native_path)],"Cargo native link search path differs from original archive")
    archives=value["native_archives"]
    require(isinstance(archives,dict) and archives,"missing actual native archive manifest")
    require(str(native_path/"liblibsql.a") in archives,"original link archive omitted from native byte manifest")
    for name,digest in archives.items():
        target=PurePosixPath(name)
        require(target.is_absolute() and ".." not in target.parts and target.is_relative_to(native_path) and target.suffix==".a",
                "native archive path escaped original Cargo build output")
        sha256_text(digest)
    retrieved,unavailable=[],[]
    for name,expected in {binary["path"]:binary["sha256"],**archives}.items():
        target=Path(name)
        if target.exists():
            require(target.is_file() and file_digest(target)==expected,"retrieved executable/native bytes differ from original build")
            retrieved.append(name)
        else:unavailable.append(name)
    native_directory=Path(native_path)
    if native_directory.is_dir():
        actual={}
        for archive in native_directory.rglob("*.a"):
            require(archive.resolve().is_relative_to(native_directory.resolve()),"retrieved native archive escaped build output")
            actual[str(archive)]=file_digest(archive)
        require(set(actual)<=set(archives),"retrieved native archive inventory differs from original Cargo build")
        for name,digest in actual.items():
            equal(digest,archives[name],"retrieved native archive bytes differ from original Cargo build")
    source_root=Path(source_root) if source_root is not None else Path(value["source_root"])
    try:local_sources=source_inventory(source_root,profile)
    except FileNotFoundError:local_sources=None
    source_matches=local_sources==inputs
    require(not require_artifacts or not unavailable,"original executable/native bytes unavailable; only explicit offline partial audit is possible")
    require(not require_artifacts or source_matches,"current source manifest differs from the frozen release build")
    full=not unavailable and source_matches
    return {"status":"verified","verification_scope":"full" if full else "archived_source_and_cargo_only",
            "sha256":file_digest(path),"source_files_verified":len(inputs),"source_bytes_verified":source_bytes,"profile":profile,
            "cargo_process_exit_code":0,"original_cargo_build_finished":True,"binary":binary,
            "local_source_manifest_matches":source_matches,"retrieved_artifacts":retrieved,"unavailable_artifacts":unavailable,
            "executable_native_bytes":"verified" if not unavailable else "NOT_AVAILABLE"}
