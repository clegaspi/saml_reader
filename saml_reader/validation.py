"""
Validation classes
"""

import networkx as nx

PASS = 1
FAIL = 0
NOT_RUN = -1


class TestDefinition:
    def __init__(self, title, test_function, dependencies=None, required_context=None):
        self.status = NOT_RUN
        self.dependencies = set(dependencies) if dependencies else set()
        self.title = title or ""
        self.required_context = set(required_context) if required_context else set()
        if not callable(test_function):
            raise ValueError("test_function not a callable object")
        self._func = test_function
        self._result_metadata = None

    def add_dependency(self, dependency):
        self.dependencies.add(dependency)

    def remove_dependency(self, dependency):
        if dependency in self.dependencies:
            self.dependencies.remove(dependency)

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
            self.status = result[0]
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
        # This is bad hash right now
        return hash(self.title)


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
                   for dependency in test.dependencies)

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
        self._test_graph.add_nodes_from(self._tests)
        test_lookup = {test.title: test for test in self._tests}
        for test in self._tests:
            for dependency in test.dependencies:
                self._test_graph.add_edge(test_lookup[dependency], test)

    def _run_suite(self):
        tests_to_run = self._get_next_set_of_tests()
        count = 1
        while tests_to_run:
            # print(f"Round {count}")
            for test in tests_to_run:
                # print(f"Running test {test.title}")
                if test.run(self._context):
                    self._test_graph.remove_node(test)
            tests_to_run = self._get_next_set_of_tests()
            count += 1

        self._results = dict()
        for test in self._tests:
            # print(f"Test: {test.title}, Result: {test.status}")
            self._results[test] = test.status

    def _get_next_set_of_tests(self):
        return [test for test, n_unmet_dependencies in self._test_graph.in_degree
                if n_unmet_dependencies == 0 and test.status == NOT_RUN]

    def has_run(self):
        return self._has_run

    def get_results(self):
        if self.has_run():
            return {k.title: v for k, v in self._results.items()}
        raise ValueError("Test suite not run!")

