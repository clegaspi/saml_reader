"""
These classes implement a graph-based approach to running a battery of validation tests
where one test can depend on the pass/fail state of another test.
"""

import networkx as nx

# Test completion states
TEST_PASS = 1
TEST_FAIL = 0
TEST_NOT_RUN = -1


class TestDefinition:
    def __init__(self, title, test_function, dependencies=None, required_context=None):
        self.status = TEST_NOT_RUN
        self.dependencies = dict()
        for dependency in dependencies or []:
            if isinstance(dependency, (str, TestDefinition)):
                self.dependencies[dependency] = TEST_PASS
            elif isinstance(dependency, tuple):
                if len(dependency) != 2:
                    raise ValueError("Dependency must be a 2-length tuple, str, or TestDefinition")
                test, required_result = dependency
                if required_result not in (TEST_PASS, TEST_FAIL):
                    raise ValueError("Dependency result must be TEST_PASS or TEST_FAIL")
                self.dependencies[test] = required_result
        self.title = title or ""
        self.required_context = set(required_context) if required_context else set()
        if not callable(test_function):
            raise ValueError("test_function not a callable object")
        self._func = test_function
        self._result_metadata = None

    def add_dependency(self, dependency, required_result=TEST_PASS):
        self.dependencies[dependency] = required_result

    def remove_dependency(self, dependency):
        if dependency in self.dependencies:
            self.dependencies.pop(dependency)

    def add_required_context_value(self, context):
        self.required_context.add(context)

    def remove_required_context_value(self, context):
        if context in self.required_context:
            self.required_context.remove(context)

    def run(self, context=None):
        if self.required_context:
            if not context:
                raise ValueError("No context provided when context values required")
            if any(x not in context for x in self.required_context):
                missing_context = self.required_context - self.required_context.intersection(set(context.keys()))
                raise ValueError(f"Missing context values for test: {missing_context}")
        result = self._func({x: context[x] for x in self.required_context})
        if isinstance(result, tuple):
            self.status = bool(result[0])
            self._result_metadata = result[1:]
        else:
            self.status = int(bool(result))
        return self.status

    def __eq__(self, other):
        if isinstance(other, str):
            return self.title == other
        elif isinstance(other, TestDefinition):
            return self.title == other.title
        raise NotImplemented

    def __hash__(self):
        return hash(self.title)

    def __str__(self):
        return self.title

    def __repr__(self):
        return self.title


class _FailedTest(TestDefinition):
    def __init__(self, test_to_monitor):
        super().__init__(
            f"Blocker for tests depending on failure of: {test_to_monitor}",
            lambda x: TEST_FAIL,
            dependencies=[test_to_monitor]
        )


class TestSuite:
    def __init__(self):
        self._tests = set()
        self._context = dict()
        self._test_graph = nx.DiGraph()
        self._results = None
        self._has_run = False

    def context_satisfies_requirements(self):
        return all(context_value in self._context
                   for test in self._tests
                   for context_value in test.required_context)

    def all_dependent_test_in_suite(self):
        return all(dependency in self._tests
                   for test in self._tests
                   for dependency in test.dependencies.keys())

    def add_test(self, test: TestDefinition, replace=True):
        if not replace and test in self._tests:
            raise ValueError(f"Suite already contains test '{test.title}'")
        self._tests.add(test)

    def remove_test(self, test):
        if test in self._tests:
            self._tests.remove(test)

    def set_context(self, context):
        self._context = context

    def run(self):
        if not self.context_satisfies_requirements():
            raise ValueError("Context is missing required values for tests")
        if not self.all_dependent_test_in_suite():
            raise ValueError("Dependency test missing")

        self._build_graph()
        self._run_suite()
        self._has_run = True

    def _build_graph(self):
        for test in self._tests:
            node_name = "PASS_" + test.title
            self._test_graph.add_node(node_name, test_object=test)

        for test in self._tests:
            for dependency, required_result in test.dependencies.items():
                child_node_name = "PASS_" + test.title
                if required_result == TEST_PASS:
                    parent_node_name = "PASS_" + str(dependency)
                elif required_result == TEST_FAIL:
                    parent_node_name = "FAIL_" + str(dependency)
                    self._test_graph.add_node(
                        parent_node_name,
                        test_object=_FailedTest(dependency)
                    )
                    self._test_graph.add_edge("PASS_" + str(dependency), parent_node_name)
                else:
                    raise ValueError("Invalid required test result!")
                self._test_graph.add_edge(parent_node_name, child_node_name)

    def _run_suite(self):
        for test in self._get_next_test():
            # print(f"Running test {test.title}")
            test.run(self._context)
            # print(f"Test: {test.title}, Result: {test.status}")

        self._results = {test: test.status for test in self._tests}

    def _get_next_test(self):
        def __yield_tests_rec(graph):
            queue_for_removal = set()
            for test_name, n_unmet_dependencies in graph.in_degree:
                test_object = graph.nodes[test_name]['test_object']
                if n_unmet_dependencies == 0 and test_object.status == TEST_NOT_RUN:
                    yield test_object
                    if test_object.status == TEST_PASS:
                        queue_for_removal.add(test_name)
                    elif test_object.status == TEST_FAIL:
                        queue_for_removal.add("FAIL_" + str(test_object))
                    else:
                        raise ValueError("Invalid test result")
            if not queue_for_removal:
                return
            graph.remove_nodes_from(queue_for_removal)
            queue_for_removal.clear()
            yield from __yield_tests_rec(graph)

        yield from __yield_tests_rec(self._test_graph)

    def has_run(self):
        return self._has_run

    def get_results(self):
        if self.has_run():
            return {k.title: v for k, v in self._results.items()}
        raise ValueError("Test suite not run!")

