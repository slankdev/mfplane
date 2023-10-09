import os
import json
from ansible.parsing.ajson import AnsibleJSONEncoder
from ansible.plugins.callback.default import CallbackModule as Base

DOCUMENTATION = '''
    name: json_export
    type: stdout
    short_description: Also export results into a JSON file if specified.
    version_added: historical
    description:
        - Export results into a JSON file (specified at JSON_EXPORT_PATH).
    extends_documentation_fragment:
      - default_callback
    requirements:
      - set as stdout in configuration
'''

# 基本的にはデフォルトの出力が欲しいので、デフォルトのcallbackモジュールを拡張したものを作成する
class CallbackModule(Base):

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'json_export'

    def __init__(self):
        super(CallbackModule, self).__init__()
        self._results = []
        self._servers = {}
        self._output_to = "/tmp/ansible_result.json"

    # v2_* メソッドをオーバーライドしてデフォルトの動作に処理を追加していく

    def v2_playbook_on_task_start(self, task, is_conditional):
        super(CallbackModule, self).v2_playbook_on_task_start(task, is_conditional)
        self._results.append({ 'name': task.get_name(), 'items': [] })
    
    def v2_runner_on_ok(self, result):
        super(CallbackModule, self).v2_runner_on_ok(result)
        self._append_result('ok', result)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        super(CallbackModule, self).v2_runner_on_failed(result)
        self._append_result('failed', result)

    def v2_runner_on_skipped(self, result):
        super(CallbackModule, self).v2_runner_on_skipped(result)
        self._append_result('skipped', result)

    def v2_runner_on_unreachable(self, result):
        super(CallbackModule, self).v2_runner_on_skipped(result)
        self._append_result('unreachable', result)

    def _append_result(self, result_type, result):
        lastResults = self._results[-1]['items']
        host_name = result._host.get_name()

        rawResult = result._result
        essentialResult = {}
        for key in ["changed", "start", "end", "stdout", "stdout_lines", "stderr", "stderr_lines"]:
            if key in rawResult:
                essentialResult[key] = rawResult[key]

        lastResults.append({
            'host_name': host_name,
            'type': result_type,
            'result': essentialResult
        })
        self._servers[host_name] = True

    # 実行結果出力時（実行の最後）にJSONファイルを出力する
    def v2_playbook_on_stats(self, stats):
        super(CallbackModule, self).v2_playbook_on_stats(stats)
        if self._output_to:
            with open(self._output_to, "w") as f:
                json.dump({
                    'results': self._results,
                    'host_names': list(self._servers.keys())
                }, f, cls=AnsibleJSONEncoder, indent=2, ensure_ascii=False, sort_keys=True)
